#!/usr/bin/env -S python3 -u
import json
import subprocess
import os
import re
from utils import *

def validate_build_id(build_id):
    if not re.match(r'^\d+$', str(build_id)):
        fail(f"Invalid build_id format: {build_id}")
    return build_id

def validate_version_component(component, name):
    if not re.match(r'^[a-z0-9.-]+$', component, re.IGNORECASE):
        fail(f"Invalid {name} format: {component}")
    return component

def sanitize_for_github_output(value):
    sanitized = re.sub(r'[\r\n\x00-\x1f\x7f]', '', value)
    return sanitized

def release_exists(release_id):
    url = f"https://storage.googleapis.com/kernelctf-build/releases/{release_id}/cvd-host_package.tar.gz"
    status_code = requests.head(url).status_code
    
    if status_code == 200:
        return True
    if status_code == 403:
        return False
    
    fail(f"Unexpected HTTP status code for release check: {status_code} (url = {url})")

def fetch_android_build():
    API_URL = "https://androidbuildinternal.googleapis.com/android/internal/build/v3/builds"
    TARGET = "aosp_cf_x86_64_only_phone-userdebug"
    BRANCH = "aosp-android-latest-release"
    
    print(f"Fetching latest Android build for {TARGET}...")
    
    response = fetch(f"{API_URL}?branches={BRANCH}&buildAttemptStatus=complete&buildType=submitted&maxResults=1&successful=true&target={TARGET}")
    
    try:
        data = json.loads(response)
        builds = data.get('builds', [])
        
        if not builds:
            fail("No builds found in API response")
        
        build_id = builds[0].get('buildId')
        if not build_id:
            fail("No buildId found in response")
        
        # Validate build_id is numeric only
        build_id = validate_build_id(build_id)
        
        print(f"Latest build ID: {build_id}")
        return {
            'build_id': build_id,
            'target': TARGET
        }
    
    except (json.JSONDecodeError, KeyError) as e:
        fail(f"Error parsing API response: {e}")

def download_kernel_version(build_info):
    build_id = build_info['build_id']
    target = build_info['target']
    
    print(f"Fetching kernel_version.txt for build {build_id}...")
    
    try:
        result = subprocess.run(
            [
                'fetch_artifact',
                f'-target={target}',
                f'-build_id={build_id}',
                '-artifact=kernel_version.txt'
            ],
            capture_output=True,
            text=True,
            check=True
        )
        
        if not os.path.exists('kernel_version.txt'):
            fail("kernel_version.txt not found after download")
        
        with open('kernel_version.txt', 'r') as f:
            kernel_version_string = f.read().strip()
        
        print(f"Kernel version string: {kernel_version_string}")
        
        os.remove('kernel_version.txt')
        
        return kernel_version_string
    
    except subprocess.CalledProcessError as e:
        fail(f"fetch_artifact failed: {e.stderr}")

def parse_kernel_version(kernel_version_string):
    # Example: "6.12.23-android16-5-g2cc84bbe1269-ab13603476"
    parts = kernel_version_string.split('-')
    
    if len(parts) < 2:
        fail(f"Invalid kernel version format: {kernel_version_string}")
    
    kernel_version = validate_version_component(parts[0], "kernel_version")
    android_version = validate_version_component(parts[1], "android_version")
    
    print(f"Kernel version: {kernel_version}")
    print(f"Android version: {android_version}")
    
    return {
        'kernel_version': kernel_version,
        'android_version': android_version
    }

def get_latest_android_release():
    # Fetch latest build info
    build_info = fetch_android_build()
    
    # Download kernel version info
    kernel_version_string = download_kernel_version(build_info)
    
    # Parse kernel version
    version_info = parse_kernel_version(kernel_version_string)
    
    # Example build release ID: android16-6.12.23-x86_64-14421689
    release_id = f"{version_info['android_version']}-{version_info['kernel_version']}-x86_64-{build_info['build_id']}"
    
    # Sanitize for GitHub Actions output (prevent injection)
    release_id = sanitize_for_github_output(release_id)
    
    print(f"Release ID: {release_id}")
    
    # Check if release already exists
    if release_exists(release_id):
        print("Release already exists in GCS, skipping")
        return []
    
    print("Release does not exist in GCS, will proceed with build")
    return [{
        "releaseId": release_id,
        "branch": None
    }]

releases = get_latest_android_release()

ghSet("OUTPUT", "releases=" + json.dumps(releases))
print(f"Generated releases output: {json.dumps(releases)}")
