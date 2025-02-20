/*
Copyright (c) 2017-2024 Divested Computing Group
Copyright (c) 2025 steadfasterX <steadfasterX #AT# binbash |dot| rocks >

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Sorter {

  private static HashMap<String, CVE> cves = new HashMap<>();
  private static ArrayList<String> numberedBlocks = new ArrayList<>();
  private static String lastCheckedLine = "";

  public static void sort(File manifest) {
    Common.initEnv();
    try {
      Scanner s = new Scanner(manifest);
      String curId = "";
      ArrayList<String> lines = new ArrayList<>();
      while (s.hasNextLine()) {
        String line = s.nextLine();
        if (line.startsWith("#Last checked")) {
          lastCheckedLine = line;
        } else if (line.matches("^(CVE|LVT|\\d+\\-).*")) {
          if (curId.length() > 0) {
            addOrUpdateCVE(curId, lines);
            curId = "";
            lines = new ArrayList<>();
          }
          curId = line;
        } else {
          lines.add(line);
        }
      }
      if (curId.length() > 0) {
        addOrUpdateCVE(curId, lines);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }

    ArrayList<CVE> cveList = new ArrayList<>(cves.values());
    Collections.sort(cveList, new AlphanumComparator());

    if (!lastCheckedLine.isEmpty()) {
      System.out.println(lastCheckedLine);
    }

    for (CVE cve : cveList) {
      if (cve.getLines().isEmpty()) {
        continue;
      }
      if (cve.getId().matches("^\\d+\\-.*")) {
        numberedBlocks.add(cve.getId());
        continue;
      }
      System.out.println(cve.getId());
      ArrayList<String> sortedLines = sortLinesWithinBlock(cve.getLines());
      for (String line : sortedLines) {
        System.out.println(line);
      }
    }

    for (String blockId : numberedBlocks) {
      CVE cve = cves.get(blockId);
      if (cve.getLines().isEmpty()) {
        continue;
      }
      System.out.println(cve.getId());
      ArrayList<String> sortedLines = sortLinesWithinBlock(cve.getLines());
      for (String line : sortedLines) {
        System.out.println(line);
      }
    }
  }

  private static void addOrUpdateCVE(String id, ArrayList<String> lines) {
    if (cves.containsKey(id)) {
      CVE existingCVE = cves.get(id);
      Set<String> uniqueHashes = new HashSet<>();
      for (String line : existingCVE.getLines()) {
        uniqueHashes.add(extractHash(line));
      }
      for (String line : lines) {
        if (!uniqueHashes.contains(extractHash(line))) {
          existingCVE.getLines().add(line);
          uniqueHashes.add(extractHash(line));
        }
      }
    } else {
      cves.put(id, new CVE(id, lines));
    }
  }

  private static String extractHash(String line) {
    int hashIndex = line.lastIndexOf("=");
    if (hashIndex != -1) {
      return line.substring(hashIndex + 1);
    }
    hashIndex = line.lastIndexOf("/");
    if (hashIndex != -1) {
      return line.substring(hashIndex + 1);
    }
    return line;
  }

  private static ArrayList<String> sortLinesWithinBlock(ArrayList<String> lines) {
    ArrayList<String> depends = new ArrayList<>();
    ArrayList<String> linksTop = new ArrayList<>();
    ArrayList<String> linksMiddle = new ArrayList<>();
    ArrayList<String> linksBottom = new ArrayList<>();
    ArrayList<String> others = new ArrayList<>();

    for (String line : lines) {
      if (line.startsWith("Depends")) {
        depends.add(line);
      } else if (line.matches("^Link - \\^\\d")) {
        linksTop.add(line);
      } else if (line.matches("^Link - \\d")) {
        linksMiddle.add(line);
      } else if (line.startsWith("Link - ")) {
        linksBottom.add(line);
      } else {
        others.add(line);
      }
    }

    Collections.sort(linksTop, new LinkComparator());
    Collections.sort(linksMiddle, new LinkComparator());
    Collections.sort(linksBottom);

    ArrayList<String> sortedLines = new ArrayList<>();
    sortedLines.addAll(depends);
    sortedLines.addAll(linksTop);
    sortedLines.addAll(linksMiddle);
    sortedLines.addAll(linksBottom);
    sortedLines.addAll(others);

    return sortedLines;
  }

  public static class CVE {
    private String id;
    private ArrayList<String> lines;

    public CVE(String id, ArrayList<String> lines) {
      this.id = id.replaceAll("\u00AD", "-").replaceAll("--", "-");
      this.lines = lines;
    }

    public String getId() {
      return id;
    }

    public ArrayList<String> getLines() {
      return lines;
    }

    public void setLines(ArrayList<String> lines) {
      this.lines = lines;
    }

    @Override
    public String toString() {
      return getId();
    }
  }

  public static class AlphanumComparator implements Comparator<CVE> {
    private final Pattern pattern = Pattern.compile("(\\D*)(\\d*)");

    @Override
    public int compare(CVE cve1, CVE cve2) {
      Matcher m1 = pattern.matcher(cve1.getId());
      Matcher m2 = pattern.matcher(cve2.getId());

      while (m1.find() && m2.find()) {
        int nonDigitCompare = m1.group(1).compareTo(m2.group(1));
        if (nonDigitCompare != 0) {
          return nonDigitCompare;
        }

        if (m1.group(2).isEmpty() && m2.group(2).isEmpty()) {
          return 0;
        } else if (m1.group(2).isEmpty()) {
          return -1;
        } else if (m2.group(2).isEmpty()) {
          return 1;
        }

        int digitCompare = Long.compare(Long.parseLong(m1.group(2)), Long.parseLong(m2.group(2)));
        if (digitCompare != 0) {
          return digitCompare;
        }
      }

      return m1.hitEnd() ? (m2.hitEnd() ? 0 : -1) : 1;
    }
  }

  public static class LinkComparator implements Comparator<String> {
    private final Pattern pattern = Pattern.compile("Link - (\\^?\\d+(\\.\\d+)?)");

    @Override
    public int compare(String link1, String link2) {
      Matcher m1 = pattern.matcher(link1);
      Matcher m2 = pattern.matcher(link2);

      if (m1.find() && m2.find()) {
        String version1 = m1.group(1);
        String version2 = m2.group(1);

        if (version1.startsWith("^") && version2.startsWith("^")) {
          return Double.compare(Double.parseDouble(version2.substring(1)), Double.parseDouble(version1.substring(1)));
        } else if (version1.startsWith("^")) {
          return -1;
        } else if (version2.startsWith("^")) {
          return 1;
        } else {
          return Double.compare(Double.parseDouble(version2), Double.parseDouble(version1));
        }
      }

      return link1.compareTo(link2);
    }
  }
}
