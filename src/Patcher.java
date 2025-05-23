/*
Copyright (c) 2017-2024 Divested Computing Group
Copyright (c) 2025 steadfasterX <steadfasterX #AT# binbash |dot| rocks >

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

public class Patcher {

  private static final int MODE_DIRECT = 0;
  private static final int MODE_WORKSPACE = 1;
  private static int MODE_CURRENT = -1;
  private static File workspacePath = null;
  private static final String patchesPathScriptLinux = "\\$DOS_PATCHES_LINUX_CVES/";
  private static final String scriptPrefix = "android_";
  private static boolean looseVersions = false;
  private static boolean looseVersionsExtreme = false;
  private static boolean looseVersionsReverse = false;
  private static boolean gitMailbox = false;

  public static void patch(String[] args) {
    if(System.getenv("DOS_PATCHER_LOOSE_VERSIONS") != null) {
      looseVersions = System.getenv("DOS_PATCHER_LOOSE_VERSIONS").equalsIgnoreCase("true");
    }
    if(System.getenv("DOS_PATCHER_LOOSE_VERSIONS_EXTREME") != null) {
      looseVersionsExtreme = System.getenv("DOS_PATCHER_LOOSE_VERSIONS_EXTREME").equalsIgnoreCase("true");
    }
    if(System.getenv("DOS_PATCHER_LOOSE_VERSIONS_REVERSE") != null) {
      looseVersionsReverse = System.getenv("DOS_PATCHER_LOOSE_VERSIONS_REVERSE").equalsIgnoreCase("true");
    }
    if(System.getenv("DOS_PATCHER_GIT_AM") != null) {
      gitMailbox = System.getenv("DOS_PATCHER_GIT_AM").equalsIgnoreCase("true");
    }
    if (args.length == 1) {
      System.out.println("Mode options are: direct and workspace");
    } else {
      if (args[1].equals("direct")) {
        if (args.length >= 5) {
          MODE_CURRENT = MODE_DIRECT;
          File patchesPath = new File(ensureLeadingSlash(args[2]));
          File outputDir = new File(ensureLeadingSlash(args[3]));

          int c = 0;
          for (String repo : args) {
            if (c < 4) {
              c++;
              continue;
            }
            File repoPath = new File(ensureLeadingSlash(repo.split(":")[0]));
            String repoName = repo.split(":")[1];
            checkAndGenerateScript(repoPath, repoName, patchesPath, outputDir, null);
          }
        } else {
          System.out
              .println("Invalid args: patch direct $patchesPath $outputDir $repoPath:repoName...");
        }
      } else if (args[1].equals("workspace")) {
        if (args.length >= 6) {
          MODE_CURRENT = MODE_WORKSPACE;
          workspacePath = new File(ensureLeadingSlash(args[2]));
          File patchesPath = new File(ensureLeadingSlash(args[3]));
          File outputDir = new File(ensureLeadingSlash(args[4]));

          int c = 0;
          for (String repo : args) {
            if (c < 5) {
              c++;
              continue;
            }
            String repoName = repo;
            File repoPath = getRepoPath(workspacePath, repoName);
            checkAndGenerateScript(repoPath, repoName, patchesPath, outputDir, null);
          }
        } else {
          System.out.println(
              "Invalid args: patch workspace $workspace $patchesPath $outputDir repoName...");
        }
      }
    }

  }

  private static String ensureLeadingSlash(String dir) {
    if (!dir.endsWith("/")) {
      dir += "/";
    }
    return dir;
  }

  private static File getRepoPath(File workspace, String repoName) {
    return new File(ensureLeadingSlash(
        ensureLeadingSlash(workspace.toString()) + repoName.replaceAll("_", "/")));
  }

  private static boolean doesRepoExist(File repoPath) {
    return repoPath.exists();
  }

  private static void checkAndGenerateScript(File repoPath, String repoName, File patchesPath,
      File outputDir, ArrayList<String> scriptCommands) {
    if (doesRepoExist(repoPath)) {
      System.out.println("Starting on " + repoName);
      boolean firstRun = true;
      int firstPass = 0;
      if (scriptCommands == null) {
        scriptCommands = new ArrayList<>();
      } else {
        firstRun = false;
        firstPass = scriptCommands.size();
      }

      Version repoVersion = Common.getKernelVersion(repoPath);
      String patchesPathScript = patchesPathScriptLinux;
      boolean ignoreMajor = false;

      // The top-level directory contains all patchsets
      List<File> patchSets = Arrays.asList(patchesPath.listFiles(File::isDirectory));
      if (patchSets != null && patchSets.size() > 0) {
        Collections.sort(patchSets, new AlphanumComparator());

        // Iterate over all patchsets
        for (File patchSet : patchSets) {
          String patchSetName = patchSet.getName();
          System.out.println("\tChecking " + patchSetName);
          if (!firstRun && patchSetName.equals("0001-LinuxIncrementals")) {
            System.out.println("\t\tThis is a second pass, skipping Linux incrementals");
            continue;
          }

          // Get all available versions for a patchset
          File[] patchSetVersions = patchSet.listFiles(File::isDirectory);
          Arrays.sort(patchSetVersions, new AlphanumComparator());
          ArrayList<String> versions = new ArrayList<>();
          // Check which versions are applicable
          boolean directMatchAvailable = false;
          for (File patchSetVersion : patchSetVersions) {
            if(patchSetVersion.getName().startsWith(repoVersion.getVersionFull())) {
              directMatchAvailable = true;
            }
          }

          for (File patchSetVersion : patchSetVersions) {
            String patchVersion = patchSetVersion.getName();
            if (isVersionInRange(repoVersion, patchVersion, ignoreMajor)) {
              versions.add(patchVersion);
            }
            if(!getModulePath("/" + patchVersion + "/").equals("INVALID") && new File(repoPath + "/" + getModulePath("/" + patchVersion + "/")).exists()) {
              versions.add(patchVersion);
            }
            if(!directMatchAvailable && looseVersions) {
              //ugly hack to help 3.x
              //4.4 was maintained well and has all the patches
              //3.18 currently has a ton of patches thanks to maintenance from Google/Linaro up until 2021-10
              //3.4 has many backports from the community
              //3.10 and far more so 3.0 are in not great shape
              if (repoVersion.getVersionFull().startsWith("3.0") && (patchVersion.equals("3.4") || (looseVersionsExtreme && (patchVersion.equals("3.10") || patchVersion.equals("3.18") || patchVersion.equals("4.4"))))) {
                versions.add(patchVersion);
              }
              if (repoVersion.getVersionFull().startsWith("3.4") && (patchVersion.equals("3.10") || (looseVersionsExtreme && (patchVersion.equals("3.18") || patchVersion.equals("4.4"))))) {
                versions.add(patchVersion);
              }
              if (repoVersion.getVersionFull().startsWith("3.10") && (patchVersion.equals("3.18") || (looseVersionsExtreme && (patchVersion.equals("4.4"))))) {
                versions.add(patchVersion);
              }
              if (repoVersion.getVersionFull().startsWith("3.18") && (patchVersion.equals("4.4") || (looseVersionsExtreme && (patchVersion.equals("4.9"))))) {
                versions.add(patchVersion);
              }
              if (repoVersion.getVersionFull().startsWith("4.4") && patchVersion.equals("4.9")) {
                versions.add(patchVersion);
              }
              if (repoVersion.getVersionFull().startsWith("4.9") && (patchVersion.equals("4.14") || (looseVersionsExtreme && (patchVersion.equals("4.19"))))) {
                versions.add(patchVersion);
              }
              if (repoVersion.getVersionFull().startsWith("4.14") && patchVersion.equals("4.19")) {
                versions.add(patchVersion);
              }
              //Try to apply 3.4 patches to 3.10 regardless of 3.18 patches being available
              //Can result in 3.4 patches being applied instead of more appropriate 3.18 patches
              //if (looseVersionsReverse && repoVersion.getVersionFull().startsWith("3.10") && patchVersion.equals("3.4")) {
              //  versions.add(patchVersion);
              //}
            }
          }

          //Conservatively apply 3.4 patches to 3.10 if 3.18 patches aren't available
          if(!directMatchAvailable && looseVersions && looseVersionsReverse && repoVersion.getVersionFull().startsWith("3.10")) {
            boolean is318Available = false;
            boolean is34Available = false;
            for (File patchSetVersion : patchSetVersions) {
              if(patchSetVersion.getName().startsWith("3.18")) {
                is318Available = true;
              }
              if(patchSetVersion.getName().startsWith("3.4")) {
                is34Available = true;
              }
            }
            if(!is318Available && is34Available) {
              versions.add("3.4");
            }
          }

          boolean depends = new File(patchSet.toString() + "/depends").exists();

          // Iterate over all applicable versions
          for (String version : versions) {
            File[] patches =
                new File(patchSet.getAbsolutePath() + "/" + version + "/").listFiles(File::isFile);
            if (patches != null && patches.length > 0) {
              Arrays.sort(patches, new AlphanumComparator());

              // Check the patches
              if (depends) {
                ArrayList<String> commands =
                    doesPatchSetApply(repoPath, patchesPath, patches, true, patchesPathScript);
                if (commands != null) {
                  scriptCommands.addAll(commands);
                }
              } else {
                for (File patch : patches) {
                  if (isValidPatchName(patch.getName())) {
                    String command = doesPatchApply(repoPath, patchesPath, patch.getAbsolutePath(),
                        true, "", patchesPathScript);
                    if (command != null && !scriptCommands.contains(command)) {
                      scriptCommands.add(command);
                    }
                  }
                }
              }
            }
          }
        }
      } else {
        System.out.println("\tNo patches available");
      }

      if (scriptCommands.size() > 0) {
        if (firstRun) {
          System.out.println("\tPerforming second pass to check for unmarked dependents");
          checkAndGenerateScript(repoPath, repoName, patchesPath, outputDir, scriptCommands);
        } else {
          System.out.println("\tAttempted to check all patches against " + repoName);
          System.out.println("\tApplied " + scriptCommands.size() + " patch(es) - 1st Pass: "
              + firstPass + ", 2nd Pass: " + (scriptCommands.size() - firstPass));
          writeScript(repoName, outputDir, scriptCommands);
        }
      }
    } else {
      System.out.println("Invalid repo: " + repoName);
    }
  }

  private static void writeScript(String repoName, File outputDir,
      ArrayList<String> scriptCommands) {
    try {
      String script = "";
      if (MODE_CURRENT == MODE_WORKSPACE) {
        script = outputDir + "/" + scriptPrefix + repoName + ".sh";
      } else if (MODE_CURRENT == MODE_DIRECT) {
        script = outputDir + "/" + repoName + ".sh";
      }
      PrintWriter out = new PrintWriter(script, "UTF-8");

      out.println("#!/bin/bash");
      out.println("extract_patch_author() {");
      out.println("    local author=$(head -n 6 \"$1\" | grep 'From:' | sed 's/From: //')");
      out.println("    echo \"${author:-$CVE_GIT_AUTHOR}\"");
      out.println("}");
      out.println("extract_patch_date() {");
      out.println("    local date=$(head -n 6 \"$1\" | grep 'Date:' | sed 's/Date: //')");
      out.println("    echo \"${date:-$(date)}\"");
      out.println("}");
      out.println("extract_patch_subject() {");
      out.println("    local subject=$(head -n 6 \"$1\" | grep 'Subject:' | sed -E 's/Subject: (\\[PATCH\\] )?//')");
      out.println("    local pname=$(get_patch_name \"$1\")");
      out.println("    echo -e \"${subject:-$pname}\\n\\napplied by CVE kernel patcher:\\n${DOS_PATCHER_URI_KERNEL}/$pname\"");
      out.println("}");
      out.println("get_patch_name() {");
      out.println("    local patch_path=\"$1\"");
      out.println("    IFS='/' read -r -a parts <<< \"$patch_path\"");
      out.println("    local len=${#parts[@]}");
      out.println("    if (( len >= 3 )); then");
      out.println("        echo \"${parts[len-3]}/${parts[len-2]}/${parts[len-1]}\"");
      out.println("    else");
      out.println("        echo \"$patch_path\"");
      out.println("    fi");
      out.println("}");

      if (MODE_CURRENT == MODE_WORKSPACE) {
        out.println("if cd \"$DOS_BUILD_BASE\"\"" + repoName.replaceAll("_", "/") + "\"; then");
      }
      for (String command : scriptCommands) {
        out.println(command);
      }
      if (MODE_CURRENT == MODE_WORKSPACE) {
        out.println("pcnt=$(git log --oneline FETCH_HEAD..|wc -l)");
        out.println("editKernelLocalversion \"-p${pcnt}\"");
        out.println("else echo \"" + repoName + " is unavailable, not patching.\";");
        out.println("fi;");
        out.println("cd \"$DOS_BUILD_BASE\"");
      }
      out.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static boolean isValidPatchName(String patch) {
    return patch.endsWith(".patch") || patch.endsWith(".diff");
    // return !patch.contains(".base64") && !patch.contains(".disabled") && !patch.contains(".dupe")
    // && !patch.contains(".sh");
  }

  private static String logPretty(String string, File repoPath, File patchesPath) {
    string = string.replaceAll(repoPath.toString(), "\\$repoPath");
    string = string.replaceAll(patchesPath.toString(), "\\$patchesPathRoot/");
    return string;
  }

  private static String doesPatchApply(File repoPath, File patchesPath, String patch,
      boolean applyPatch, String alternateRoot, String patchesPathScript) {
    String command = "git -C " + repoPath + " apply --check " + patch;
    if (alternateRoot.length() > 0) {
      command += " --directory=" + alternateRoot + "";
    }
    if (patch.contains("0001-LinuxIncrementals")) {
      command += " --exclude=Makefile";
    }
    try {
      if ((Common.runCommand(command + " --reverse") != 0 || patch.contains("CVE-2024-41020")) && Common.runCommand(command) == 0) {
        command = command.replaceAll(" --check", "");
        System.out.println(
            "\t\tPatch can apply successfully: " + logPretty(command, repoPath, patchesPath));
        if (applyPatch) {
          if (Common.runCommand(command) == 0) {
            System.out.println(
                "\t\t\tPatch applied successfully: " + logPretty(command, repoPath, patchesPath));
          } else {
            System.out.println("\t\t\tPatched failed to apply after being checked! "
                + logPretty(command, repoPath, patchesPath));
            return null;
          }
        }
        if(gitMailbox && isGitPatch(patch)) {
          command = command.replaceAll(" apply ", " am ");
        }

        String patchCmd = "patch -r - --no-backup-if-mismatch --forward --ignore-whitespace --verbose -p1 < ";
        String patchAuthor = "$(extract_patch_author " + patch + ")";
        String patchDate = "$(extract_patch_date " + patch + ")";
        String patchSubject = "$(extract_patch_subject " + patch + ")";
        String patchName = "$(get_patch_name " + patch + ")";

        command = "echo 'processing: " + patch + "'; " + command;
        String fallBackPatch = "|| (git am --abort 2> /dev/null; " + patchCmd + patch + "&& git add -A && GIT_AUTHOR_DATE=\"" +  patchDate+ "\" git commit --author=\"" + patchAuthor + "\" -m \"" + patchSubject + "\") || exit 44";
        command += fallBackPatch;

        return command.replaceAll(" -C " + repoPath, "")
            .replaceAll(ensureLeadingSlash(patchesPath.toString()), patchesPathScript);
      } else {
        System.out.println(
            "\t\tPatch does not apply successfully: " + logPretty(command, repoPath, patchesPath));
        if (!getModulePath(patch).equals("INVALID") && alternateRoot.equals("")) {
          System.out.println("\t\t\tThis is a module patch, attempting to apply directly!");
          String altRoot = getModulePath(patch);
          return doesPatchApply(repoPath, patchesPath, patch, applyPatch, altRoot,
              patchesPathScript);
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  private static ArrayList<String> doesPatchSetApply(File repoPath, File patchesPath,
      File[] patchset, boolean applyPatches, String patchesPathScript) {
    System.out.println("\t\tChecking dependent patchset");
    ArrayList<String> commands = new ArrayList<>();
    for (File patch : patchset) {
      if (isValidPatchName(patch.getName())) {
        String command = doesPatchApply(repoPath, patchesPath, patch.getAbsolutePath(),
            applyPatches, "", patchesPathScript);
        if (command != null) {
          commands.add(command);
        } else {
          return null;
        }
      }
    }
    return commands;
  }

  private static boolean isVersionInRange(Version repo, String patch, boolean ignoreMajor) {
    if (patch.equals("ANY")) {
      return true;
    } else if (repo.getVersionFull().equals(patch)) {
      return true;
    } else if (patch.startsWith("^")) {
      Version patchVersion = new Version(patch.replaceAll("\\^", ""));
      return repo.isLesserVersion(patchVersion, ignoreMajor);
    } else if (patch.endsWith("+")) {
      Version patchVersion = new Version(patch.replaceAll("\\+", ""));
      return repo.isGreaterVersion(patchVersion, ignoreMajor);
    } else if (patch.contains("-^")) {
      String[] patchS = patch.split("-\\^");
      Version patchVersionLower = new Version(patchS[0]);
      Version patchVersionHigher = new Version(patchS[1]);
      return (repo.isGreaterVersion(patchVersionLower, ignoreMajor)
          && repo.isLesserVersion(patchVersionHigher, ignoreMajor));
    }
    return false;
  }

  private static boolean isGitPatch(String patch) {
    try {
      Scanner file = new Scanner(new File(patch));
      String firstLine = file.nextLine();
      file.close();
      if (firstLine.contains("Mon Sep 17 00:00:00 2001")) {
        return true;
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  private static String getModulePath(String patch) {
    if (patch.contains("/audio-kernel/")) {
      return "techpack/audio";
    } else if (patch.contains("/camera-kernel/")) {
      return "techpack/camera";
    } else if (patch.contains("/dsp-kernel/")) {
      return "INVALID"; //TODO
    } else if (patch.contains("/eva-kernel/")) {
      return "drivers/media/platform";
    } else if (patch.contains("/fm-commonsys/")) {
      return "INVALID"; //TODO
    } else if (patch.contains("/graphics-kernel/")) {
      return "drivers/gpu/msm";
    } else if (patch.contains("/prima/")) {
      return "drivers/staging/prima";
    } else if (patch.contains("/qcacld-2.0/")) {
      return "drivers/staging/qcacld-2.0";
    } else if (patch.contains("/qcacld-3.0/")) {
      return "drivers/staging/qcacld-3.0";
    } else if (patch.contains("/qca-cmn/")) {
      return "drivers/staging/qca-wifi-host-cmn";
    } else if (patch.contains("/qcawifi-cmn-dev/")) {
      return "INVALID"; //TODO
    } else if (patch.contains("/qca-wifi-host-cmn/")) {
      return "drivers/staging/qca-wifi-host-cmn";
    } else if (patch.contains("/securemsm-kernel/")) {
      return "INVALID"; //TODO
    } else if (patch.contains("/video-driver/")) {
      return "techpack/video";
    } else {
      return "INVALID";
    }
  }

}
