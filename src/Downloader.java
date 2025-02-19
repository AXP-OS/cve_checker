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
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.Scanner;

public class Downloader {

  private static final String FIXED_DATE_STRING = System.getenv("CVE_PATCHER_NOT_OLDER_THAN_DATE");
  private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
  private static final SimpleDateFormat GIT_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
  private static ArrayList<CVE> cves = new ArrayList<CVE>();
  private static final String userAgent =
      "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0";

  public static void download(File manifest) {
    Common.initEnv();

    String output = "";

    // Read in all the CVEs from the manifest file
    try {
      System.out.println("Parsing...");
      File cveManifestReal = manifest;
      Scanner cve = new Scanner(cveManifestReal);
      output = cveManifestReal.getParent() + "/";
      System.out.println(output);
      String name = "";
      boolean depends = false;
      ArrayList<Link> links = new ArrayList<Link>();
      while (cve.hasNextLine()) {
        String line = cve.nextLine();
        if (line.startsWith("#")) {
          // Comment, ignore
        } else if (line.startsWith("CVE") || line.startsWith("LVT") || line.startsWith("00")
            || !cve.hasNextLine()) {
          if (name.length() > 0) {
            cves.add(new CVE(name, depends, links));
            System.out.println("\t\tAdded " + links.size() + " links");
            links = new ArrayList<Link>();
            name = "";
            depends = false;
          }
          if (cve.hasNextLine()) {
            name = line;
            System.out.println("\t" + name);
          }
        } else if (line.contains("Depends")) {
          depends = true;
        } else if (line.contains("Link - ")) {
          String[] lineS = line.split(" - ");
          String link = "";
          String version = "";
          if (lineS.length > 2) {
            version = lineS[1];
            link = lineS[2];
          } else {
            version = "ANY";
            link = lineS[1];
          }
          links.add(new Link(link, version));
          System.out.println("\t\tAdded a new link to " + link);
        }
      }
      cve.close();
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }

    System.out.println("Downloading patches...");
    boolean skipIfExists = true;
    for (CVE cve : cves) {
      if (!(skipIfExists && new File(output + cve.getId()).exists())) {
        System.out.println("\t" + cve.getId());
        // Only run if we have patches available
        if (cve.getLinks().size() > 0) {
          if (cve.getDepends()) {
            File depends = new File(output + cve.getId() + "/depends");
            depends.mkdirs();
            File dependsAdd = new File(output + cve.getId() + "/depends/.NotEmpty");
            try {
              dependsAdd.createNewFile();
            } catch (IOException e) {
              e.printStackTrace();
            }
          }
          // Iterate over all links and download if needed
          int linkC = 1;
          for (Link link : cve.getLinks()) {
            String patch = getPatchURL(link);
            if (!patch.equals("NOT A PATCH")) {
              File outDir = new File(output + cve.getId() + "/" + link.getVersion());
              outDir.mkdirs();
              String base64 = "";
              if (isBase64Encoded(link)) {
                base64 = ".base64";
              }
              String patchOutput =
                  outDir.getAbsolutePath() + "/" + String.format("%04d", linkC) + ".patch" + base64;
              boolean needDownload = false;
              if(Common.INCLUSIVE_KERNEL_PATH != null && (link.getURL().startsWith(Common.URL_LINUX_MAINLINE) || link.getURL().startsWith(Common.URL_LINUX_STABLE) || link.getURL().startsWith(Common.URL_LINUX_CIP) || link.getURL().startsWith(Common.URL_AOSP_STABLE) || link.getURL().startsWith(Common.URL_OPENELA))) {
                String commitID = null;
                if(link.getURL().contains("=")) {
                  commitID = link.getURL().split("=")[1];
                }
                if(link.getURL().contains("/+/")) {
                  commitID = link.getURL().split("/\\+/")[1];
                }
                if(link.getURL().contains("openela/kernel-lts")) {
                  commitID = link.getURL().split("https://github.com/openela/kernel-lts/commit/")[1];
                }
                if(commitID == null) {
                  System.out.println("Unable to extract commit ID for: " + patch);
                  System.exit(1);
                }
                if (isCommitDateValid(commitID, patch)) {
                    if (Common.runCommand("git -C " + Common.INCLUSIVE_KERNEL_PATH + " format-patch -1 " + commitID + " --no-signature --keep-subject --output " + patchOutput.replaceAll(".base64", "")) == 0) {
                      System.out.println("\t\t\tPulled patch directly from local repo (" + commitID + ")");
                    } else {
                      needDownload = true;
                      System.out.println("\t\t\tFailed to pull patch from local repo (" + commitID + ")");
                    }
                }
              }
              if(needDownload) {
                downloadFile(patch, new File(patchOutput), false);
                if (isBase64Encoded(link)) {
                  try {
                    Process b64dec = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c",
                        "base64 -d " + patchOutput + " > " + patchOutput.replaceAll(base64, "")});
                    while (b64dec.isAlive()) {
                      // Do nothing
                    }
                    if (b64dec.exitValue() != 0) {
                      System.out.println("Failed to decode patch - " + patch);
                      System.exit(1);
                    }
                  } catch (IOException e) {
                    e.printStackTrace();
                  }
                }
                System.out.println("\t\tDownloaded " + link.getURL());
              }
              linkC++;
            } else {
              System.out.println("NOT A PATCH - " + link.getURL());
            }
          }
        }
      }
    }
    System.out.println("Success!");
  }

  private static boolean isCommitDateValid(String commitID, String patch) {
        if (FIXED_DATE_STRING == null || FIXED_DATE_STRING.isEmpty()) {
            System.out.println("Fixed date string is not set in the environment variable.");
            return false;
        }
        if (Common.INCLUSIVE_KERNEL_PATH == null || Common.INCLUSIVE_KERNEL_PATH.isEmpty()) {
            System.out.println("Kernel directory is not set in the environment variable.");
            return false;
        }
        try {
            String commitDateStr = getCommitDateFromGit(commitID); // Extract commit date using git log
            if (commitDateStr == null) {
                System.out.println("\t\tWARNING: Commit date not found for patch: " + patch);
                return false;
            }
            Date commitDate = GIT_DATE_FORMAT.parse(commitDateStr);
            Date fixedDate = DATE_FORMAT.parse(FIXED_DATE_STRING);
            if (commitDate.before(fixedDate)){
                System.out.println("\t\tCommit date too old: " + commitDate + " for patch: " + patch);
            } else {
                System.out.println("\t\tCommit date OK (" + commitDate + ")");
            }

            return !commitDate.before(fixedDate);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
  }

  private static String getCommitDateFromGit(String commitID) {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "git -C " + Common.INCLUSIVE_KERNEL_PATH + " log -1 --format=%ci " + commitID});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String commitDateStr = reader.readLine();
            process.waitFor();
            return commitDateStr;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
  }

  private static String getPatchURL(Link link) {
    String url = link.getURL()
            .replaceAll("http://", "https://")
            .replaceAll("LINUX_KERNEL_MAINLINE=", Common.URL_LINUX_MAINLINE)
            .replaceAll("LINUX_KERNEL_STABLE=", Common.URL_LINUX_STABLE)
            .replaceAll("LINUX_KERNEL_CIP=", Common.URL_LINUX_CIP)
            .replaceAll("AOSP_KERNEL_STABLE=", Common.URL_AOSP_STABLE)
            .replaceAll("OPENELA=", Common.URL_OPENELA);
    if (url.contains("lkml.org/lkml/diff")
        || (url.contains("raw.githubusercontent") && url.endsWith(".patch"))
        || (url.contains("marc.info") && url.endsWith("q=raw"))
        || (url.contains("lore.kernel.org") && url.endsWith("/raw"))) {
      return url;
    } else if (url.contains("github.com") || url.contains("git.codelinaro.org") || url.contains("gitlab.com")) {
      return url + ".patch";
    } else if (url.contains("git.kernel.org")) {
      return url.replaceAll("cgit/", "pub/scm/").replaceAll("commit", "patch");
    } else if (url.contains("codeaurora.org")) {
      return url.replaceAll("commit", "patch");
    } else if (url.contains("android.googlesource.com") || url.contains("chromium.googlesource.com")) {
      String add = "";
      if (!url.contains("%5E%21")) {
        add += "%5E%21/";
      }
      add += "?format=TEXT";
      return url.replaceAll("/#F0", "") + add; // BASE64 ENCODED
    } else if (url.contains("review.lineageos.org") && !url.contains("topic")
        && !url.contains("#/q")) {
      int idS = 3;
      if (url.contains("#/c")) {
        idS = 5;
      }
      String id = url.split("/")[idS];
      return "https://review.lineageos.org/changes/" + id + "/revisions/current/patch?download"; // BASE64
                                                                                                 // ENCODED
    } else if (url.contains("android-review.googlesource.com") && !url.contains("topic")
        && !url.contains("#/q")) {
      int idS = 3;
      if (url.contains("#/c")) {
        idS = 5;
      }
      String id = url.split("/")[idS];
      return "https://android-review.googlesource.com/changes/" + id
          + "/revisions/current/patch?download"; // BASE64 ENCODED
    } else if (url.contains("patchwork")) {
      return (url + "/raw").replaceAll("//raw", "/raw");
    }
    return "NOT A PATCH";
  }

  private static boolean isBase64Encoded(Link link) {
    if (link.getURL().contains("android.googlesource.com")
        || link.getURL().contains("chromium.googlesource.com")
        || link.getURL().contains("review.lineageos.org")
        || link.getURL().contains("android-review.googlesource.com")) {
      return true;
    }
    return false;
  }

  public static void downloadFile(String url, File out, boolean useCache) {
    try {
      HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
      connection.setConnectTimeout(45000);
      connection.setReadTimeout(45000);
      connection.addRequestProperty("User-Agent", userAgent);
      if (useCache && out.exists()) {
        connection.setIfModifiedSince(out.lastModified());
      }
      connection.connect();
      int res = connection.getResponseCode();
      if (res != 304 && (res == 200 || res == 301 || res == 302)) {
        Files.copy(connection.getInputStream(), out.toPath(), StandardCopyOption.REPLACE_EXISTING);
      }
      connection.disconnect();
    } catch (Exception e) {
      // System.out.println("Throttling? Too many files open?");
      e.printStackTrace();
      try {
        Thread.sleep(30000L);
        downloadFile(url, out, useCache);
      } catch (Exception e1) {
        e1.printStackTrace();
      }
      // System.exit(1);
    }
  }

  public static class CVE {
    private String id;
    private boolean depends;
    private ArrayList<Link> links;

    public CVE(String id, boolean depends, ArrayList<Link> links) {
      this.id = id;
      this.depends = depends;
      this.links = links;
    }

    public String getId() {
      return id;
    }

    public boolean getDepends() {
      return depends;
    }

    public ArrayList<Link> getLinks() {
      return links;
    }
  }


  public static class Link {
    private String url;
    private String version;

    public Link(String url, String version) {
      this.url = url;
      this.version = version;
    }

    public String getURL() {
      return url;
    }

    public String getVersion() {
      return version;
    }
  }

}
