# -*- utf-8 -*-
# Author: Eritque arcus
# Date: 08/08/2023
# Description: Converts an apk to a gradle project
# License: MIT

import tqdm, os, hashlib, stat, platform, zipfile, subprocess, datetime
from shutil import copyfile, unpack_archive
from multiprocessing import Pool
from pathlib import Path

# Configure:
dex2jar_path = Path("dex2jar.zip")
apk_path = Path("test.apk")
fernflower_path = Path("fernflower.jar")
projTemplate_path = Path("ProjectTemplate.zip")
output_path = Path("output")
dex2jar_threads = 5
fernflower_threads = 5
fernflower_jvm_args = []

# path helpers
dex2jar_unzip_path = output_path.joinpath("dex2jar")
if platform.system() == "Windows":
    dex2jar_bin_file = dex2jar_unzip_path.joinpath("d2j-dex2jar.bat")
else:
    dex2jar_bin_file = dex2jar_unzip_path.joinpath("d2j-dex2jar.sh")
fernflower_unzip_file = output_path.joinpath("fernflower.jar")
project_unzip_path = output_path.joinpath(os.path.basename(apk_path))
apk_unzip_path = output_path.joinpath("apk_unzipped")
jars_path = output_path.joinpath("jars")
decompile_jar_path = output_path.joinpath("decompiledJars")

fernflower_libs = []

def hash_file(filename):
    """ "This function returns the SHA-1 hash
    of the file passed into it"""

    # make a hash object
    h = hashlib.sha1()

    # open file for reading in binary mode
    with open(filename, "rb") as file:
        # loop till the end of the file
        chunk = 0
        while chunk != b"":
            # read only 1024 bytes at a time
            chunk = file.read(1024)
            h.update(chunk)

    # return the hex representation of digest
    return h.hexdigest()


def remove_directory_tree(start_directory: Path):
    """Recursively and permanently removes the specified directory, all of its
    subdirectories, and every file contained in any of those folders."""
    for path in start_directory.iterdir():
        if path.is_file():
            path.unlink()
        else:
            remove_directory_tree(path)
            path.rmdir()


def validPath():
    assert dex2jar_path.exists()
    assert apk_path.exists()
    assert fernflower_path.exists()
    assert projTemplate_path.exists()
    output_path.mkdir(exist_ok=True)
    dex2jar_unzip_path.mkdir(exist_ok=True)
    apk_unzip_path.mkdir(exist_ok=True)
    jars_path.mkdir(exist_ok=True)
    decompile_jar_path.mkdir(exist_ok=True)


def expandArchives():
    print("[*] Expanding archives...")

    dex2jarSHA = dex2jar_unzip_path.joinpath("dex2jarSHA")
    dex2jarSHA.touch(exist_ok=True)
    with open(dex2jarSHA, "r+") as f:
        sha = f.read()
        if sha != hash_file(dex2jar_path):
            if len(sha) != 0:
                remove_directory_tree(dex2jar_unzip_path)
                print("[-] Removed old unzipped dex2jar.zip")
            unpack_archive(dex2jar_path, dex2jar_unzip_path)
            f.write(hash_file(dex2jar_path))
            # chmod +x dex2jar_bin_file
            dex2jar_bin_file.chmod(dex2jar_bin_file.stat().st_mode | stat.S_IEXEC)
            print("[+] Extracted dex2jar.zip")
        else:
            print("[-] Skipping dex2jar.zip")

    if project_unzip_path.exists():
        proj_java_path = project_unzip_path.joinpath("app/src/main/java")
        remove_directory_tree(proj_java_path)
        print("[-] Removed old project in:", proj_java_path.absolute())
    else:
        unpack_archive(projTemplate_path, project_unzip_path)
        print("[+] Extracted ProjectTemplate.zip")

    if fernflower_unzip_file.exists() and hash_file(fernflower_unzip_file) == hash_file(
        fernflower_path
    ):
        print("[-] Skipping fernflower.jar")
    else:
        if fernflower_unzip_file.exists():
            fernflower_unzip_file.unlink()
            print("[-] Removed old fernflower.jar")
        copyfile(fernflower_path, output_path.joinpath("fernflower.jar"))
        print("[+] Copied fernflower.jar")

    apkSHA = apk_unzip_path.joinpath("apkSHA")
    apkSHA.touch(exist_ok=True)
    with open(apkSHA, "r+") as f:
        sha = f.read()
        if sha != hash_file(apk_path):
            if len(sha) != 0:
                remove_directory_tree(apk_unzip_path)
                print("[-] Removed old unzipped apk")
            with zipfile.ZipFile(apk_path, "r") as zip_ref:
                for file_info in zip_ref.infolist():
                    if file_info.filename.endswith(".dex"):
                        zip_ref.extract(file_info, path=apk_unzip_path)
            f.write(hash_file(apk_path))
            print("[+] Extracted", apk_path.absolute())
        else:
            print("[-] Skipping", apk_path.absolute())


def dex2jarSingle(dex_file: Path):
    cmd = [
        dex2jar_bin_file.absolute().as_posix(),
        "--force",
        "-o",
        jars_path.joinpath(dex_file.stem + ".jar").absolute().as_posix(),
        dex_file.absolute().as_posix(),
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    (stdout, stderr) = proc.communicate()

    if proc.returncode != 0:
        print(stderr)
        with open("error" + dex_file.name + datetime.datetime.now().strftime('%b-%d-%I%M%p-%G') + ".log", "w") as f:
            f.write("time:" + datetime.datetime.now().strftime('%b-%d-%I%M%p-%G') + "\n")
            f.write("cmd:" + str(cmd) + "\n")
            f.write("stderr:\n" + stderr.decode()  + "\n")
            f.write("stdout:\n" + stdout.decode() + "\n")
        raise Exception("dex2jar failed to convert " + dex_file.name)
    
    dexSHA = jars_path.joinpath(dex_file.name + "SHA")
    dexSHA.touch(exist_ok=True)
    with open(dexSHA, "w") as f:
        f.write(hash_file(dex_file))


def dex2jar():
    files = []
    for f in apk_unzip_path.iterdir():
        if f.is_file and f.suffix == ".dex":
            if jars_path.joinpath(f.name + "SHA").exists():
                with open(jars_path.joinpath(f.name + "SHA"), "r") as sha:
                    if sha.read() == hash_file(f):
                        continue
            files.append(f)
    with Pool(processes=dex2jar_threads) as pool:
        if len(files) == 0:
            print("[-] Skipping Converting dex to jar")
        else:
            print("[*] Converting dex to jar...")
            results = tqdm.tqdm(pool.imap_unordered(dex2jarSingle, files), total=len(files))
            tuple(results)  # grab the results


def decompile_jar(jar_file: Path):
    cmd = ["java"]
    cmd.extend(fernflower_jvm_args)
    cmd.extend(
        [
            "-jar",
            fernflower_unzip_file.absolute().as_posix(),
            "-dgs=1",
            "-log=ERROR",
            "-lit=1",
            "-mpm=300",
            "-ren=1"
        ]
    )
    cmd.extend(fernflower_libs)
    cmd.extend([
        jar_file.absolute().as_posix(),
        decompile_jar_path.absolute().as_posix()
    ])

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    (stdout, stderr) = proc.communicate()


    if proc.returncode != 0:
        print(stderr.decode())
        with open("error" + jar_file.name + datetime.datetime.now().strftime('%b-%d-%I%M%p-%G') + ".log", "w") as f:
            f.write("time:" + datetime.datetime.now().strftime('%b-%d-%I%M%p-%G') + "\n")
            f.write("cmd:" + str(cmd) + "\n")
            f.write("stderr:\n" + stderr.decode() + "\n")
            f.write("stdout:\n" + stdout.decode() + "\n")
        raise Exception("Fernflower failed to decompile jar " + jar_file.name)

    jarSHA = decompile_jar_path.joinpath(jar_file.name + "SHA")
    jarSHA.touch(exist_ok=True)
    with open(jarSHA, "w") as f:
        f.write(hash_file(jar_file))


def decompile_jars():
    global fernflower_libs
    jar_files = []
    for f in jars_path.iterdir():
        if f.is_file and f.suffix == ".jar":
            fernflower_libs.append("-e=" + f.absolute().as_posix())
            if decompile_jar_path.joinpath(f.name + "SHA").exists():
                with open(decompile_jar_path.joinpath(f.name + "SHA"), "r") as sha:
                    if sha.read() == hash_file(f):
                        continue
            jar_files.append(f)
    with Pool(processes=fernflower_threads) as pool:
        print("[*] Decompiling jars")
        results = tqdm.tqdm(
            pool.imap_unordered(decompile_jar, jar_files), total=len(jar_files)
        )
        tuple(results)  # grab the results


def unzip_decompiled_jars():
    print("[*] Unzipping decompiled jars")
    for f in tqdm.tqdm(decompile_jar_path.iterdir()):
        if f.is_file and f.suffix == ".jar":
            unpack_archive(f, project_unzip_path.joinpath("app/src/main/java"), "zip")

if __name__ == "__main__":
    print("[*] Starting apk2gradleProj.py")
    validPath()
    expandArchives()
    dex2jar()
    decompile_jars()
    unzip_decompiled_jars()
    print("[+] Done")
