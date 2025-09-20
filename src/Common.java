/*
Copyright (c) 2022-2024 Divested Computing Group
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
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;


public class Common {
    public static final String URL_LINUX_MAINLINE =
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=";
    public static final String URL_LINUX_STABLE =
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=";
    public static final String URL_LINUX_CIP =
            "https://git.kernel.org/pub/scm/linux/kernel/git/cip/linux-cip.git/commit/?id=";
    public static final String URL_AOSP_STABLE =
            "https://android.googlesource.com/kernel/common/+/";
    public static final String URL_OPENELA =
            "https://github.com/openela/kernel-lts/commit/";
    public static String INCLUSIVE_KERNEL_PATH = null;

    public static void initEnv() {
        if(System.getenv("DOS_PATCHER_INCLUSIVE_KERNEL") != null) {
            if(new File(System.getenv("DOS_PATCHER_INCLUSIVE_KERNEL")).exists()) {
                INCLUSIVE_KERNEL_PATH = System.getenv("DOS_PATCHER_INCLUSIVE_KERNEL");
            }
        }
    }

    public static int runCommand(String command) throws Exception {
	int attempts = 0;
	int maxAttempts = 2;
	int timeout = 6;
	int extendedTimeout = 10;

	while (attempts < maxAttempts) {
	  Process process = Runtime.getRuntime().exec(command);
	  ExecutorService executor = Executors.newSingleThreadExecutor();
	  Future<?> future = executor.submit(() -> {
	    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
		 BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
	      String line;
	      while ((line = reader.readLine()) != null) {
		System.out.println(line);
	      }
	      // Uncomment the following lines if you want to read error stream as well
	      // while ((line = errorReader.readLine()) != null) {
	      //   System.err.println(line);
	      // }
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	  });

	  try {
	    if (!process.waitFor(timeout, TimeUnit.SECONDS)) {
	      process.destroy();
	      throw new TimeoutException("Command timed out");
	    }
	    future.get();  // Ensure output is fully processed
	    return process.exitValue();  // Command executed successfully
	  } catch (TimeoutException e) {
	    attempts++;
	    timeout = extendedTimeout;  // Increase the timeout duration for the next attempt
	    if (attempts >= maxAttempts) {
	      process.destroy();
	      throw e;  // Rethrow the exception if max attempts are reached
	    }
	  } finally {
	    executor.shutdown();
	    if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
	      executor.shutdownNow();
	    }
	  }
	}
	return -1;  // This line should never be reached
    }

    public static Version getKernelVersion(File kernelMakefile) {
        try {
            return getKernelVersion(new Scanner(new File(kernelMakefile + "/Makefile")), false);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Version getKernelVersion(Scanner kernelMakefile, boolean quiet) {
        String kernelVersion = "";
        try {
            while (kernelMakefile.hasNextLine()) {
                String line = kernelMakefile.nextLine().trim();
                if (line.startsWith("VERSION = ")) {
                    kernelVersion = line.split("= ")[1];
                }
                if (line.startsWith("PATCHLEVEL = ")) {
                    kernelVersion += "." + line.split("= ")[1];
                }
/*                if (line.startsWith("SUBLEVEL = ")) {
                    if(!line.split("= ")[1].equals("0")) {
                        kernelVersion += "." + line.split("= ")[1];
                    }
                }*/
                if (line.startsWith("NAME = ")) {
                    break;
                }
            }
            kernelMakefile.close();
            if(!quiet) {
                System.out.println("Detected kernel version " + kernelVersion);
            }
            return new Version(kernelVersion);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Version getPatchVersion(String commitID) {
        if(INCLUSIVE_KERNEL_PATH == null) {
            System.out.println("Kernel repo unavailable!");
            System.exit(1);
        }
        try {
            ProcessBuilder gitShow = new ProcessBuilder("git", "-C", INCLUSIVE_KERNEL_PATH, "show", commitID + ":Makefile");
            Process gitShowExec = gitShow.start();
/*            if(!gitShowExec.waitFor(100, TimeUnit.MILLISECONDS)) {
                gitShowExec.destroy();
                return null;
            }*/
/*            if (gitShow.exitValue() != 0) {
                System.out.println("Failed to get patch version " + commitID);
                System.exit(1);
            }*/
            Scanner output = new Scanner(gitShowExec.getInputStream());
            return getKernelVersion(output, true);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
