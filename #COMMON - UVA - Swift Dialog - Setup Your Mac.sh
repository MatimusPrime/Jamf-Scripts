#!/bin/bash

####################################################################################################
#
#
#
# Setup Your Mac via swiftDialog
# https://snelson.us/sym
#
####################################################################################################
#
# HISTORY
#
#   Version 1.7.0, 01-Feb-2023, Dan K. Snelson (@dan-snelson)
#   - Adds compatibility for and leverages new features of swiftDialog 2.1
#   - Addresses Issues Nos. 30 & 31
#
#   Version 1.7.1, 07-Feb-2023, Dan K. Snelson (@dan-snelson)
#   - Addresses [Issue No. 35](https://github.com/dan-snelson/dialog-scripts/issues/35)
#   - Improves user-interaction with `helpmessage` under certain circumstances (thanks, @bartreardon!)
#   - Increased `debugMode` delay (thanks for the heads-up, @Lewis B!)
#   - Changed Banner Image (to something much, much smaller)
#
####################################################################################################



####################################################################################################
#
# Global Variables
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Script Version, Jamf Pro Script Parameters and default Exit Code
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

scriptVersion="1.7.1"
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/
scriptLog="${4:-"/var/tmp/uva.itsemp.jamfcloud.log"}"                       # Your organization's default location for client-side logs
triggerarray="/var/tmp/triggerarray.json"                                   #Location of API created trigger JSON
departmentarray="/var/tmp/departmentrarray.json"                            #Location of API created department welcome JSON
debugMode="${5:-"false"}"                                                 # [ true | verbose (default) | false ]
welcomeDialog="${6:-"true"}"                                                # [ true (default) | false ]
completionActionOption="${7:-"wait"}"                           # [ wait | sleep (with seconds) | Shut Down | Shut Down Attended | Shut Down Confirm | Restart | Restart Attended (default) | Restart Confirm | Log Out | Log Out Attended | Log Out Confirm ]
#requiredMinimumBuild="${8:-""}"                                          # Your organization's required minimum build of macOS to allow users to proceed
#outdatedOsAction=${9:-"/System/Library/CoreServices/Software Update.app"}   # Jamf Pro Self Service policy for operating system ugprades (i.e., "jamfselfservice://content?entity=policy&id=117&action=view") 
reconOptions=""                                                             # Initialize dynamic recon options; built based on user's input at Welcome dialog
exitCode="0"                                                                # Default exit code (i.e., "0" equals sucess)

#API
apiUser="apiuser"
apiPass="V&prbEM#n&5SYD3"


#JAMF
jamfBinary="/usr/local/bin/jamf"
jssBase="https://itsemp.jamfcloud.com"


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Operating System and currently logged-in user variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

osVersion=$( sw_vers -productVersion )
osBuild=$( sw_vers -buildVersion )
osMajorVersion=$( echo "${osVersion}" | awk -F '.' '{print $1}' )
loggedInUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )
timestamp=$( date +%Y-%m-%d\ %H:%M:%S )
filetime=$( date +%Y-%m-%d-%H-%M-%S )


####################################################################################################
#
# Pre-flight Checks
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Initiate Pre-flight Checks
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

echo -e "\n###\n# Setup Your Mac (${scriptVersion})\n# https://snelson.us/sym\n###\n"
echo "${timestamp} - Pre-flight Check: Initiating …"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Confirm script is running as root
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ $(id -u) -ne 0 ]]; then
    echo "${timestamp} - Pre-flight Check: This script must be run as root; exiting."
    exit 1
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#Install UVA Branding media
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


BANNER_IMAGE_PATH="/Library/Application Support/JAMF/UVA Branding/logos/COMMON-UVA-CENTERED-TEXT-BLUE.png"
#Copy Branding if it does not exist
if [ -f "$BANNER_IMAGE_PATH" ]; then
   	echo "$BANNER_IMAGE_PATH exists."
else 
   	echo "$BANNER_IMAGE_PATH does not exist."
	$jamfBinary policy -event commonuvabranding
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Gather Jamf information for this machine via API
#   *Assigned Site
#   *Site Departments with Site prefix
#   *All policies for site with category SITEPREFIX - Provisioning
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#CHECK VERSION OF MACOS
ver=$(sw_vers | grep ProductVersion | cut -d':' -f2 | tr -d ' ' | xargs)
shortver="${ver:0:2}"
echo "${timestamp} - Pre-flight Check: MacOS Version $ver"
echo "${timestamp} - Pre-flight Check: MacOS Major Version only $shortver"

#Detect Big Sur and set correct xpath variable
BigSur=11
if [ "$shortver" -ge "$BigSur" ]
then
    echo "${timestamp} - Pre-flight Check: xpath -e being used"
    xpath="xpath -e"
else
    echo "${timestamp} - Pre-flight Check: xpath being used"
    xpath="xpath"
fi

echo "${timestamp} - Pre-flight Check: Getting API Auth Bearer Token"
#created base64-encoded credentials
encodedCredentials=$( printf "$apiUser:$apiPass" | /usr/bin/iconv -t ISO-8859-1 | /usr/bin/base64 -i - )

# generate an auth token
authToken=$( /usr/bin/curl "$jssBase/uapi/auth/tokens" \
--silent \
--request POST \
--header "Authorization: Basic $encodedCredentials" )

#parse authToken for token, omit expiration
token=$( /usr/bin/awk -F \" '{ print $4 }' <<< "$authToken" | /usr/bin/xargs )


#get the System Serial Number of this computer
SerialNumber=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}')
echo "${timestamp} - Pre-flight Check: This Computers serial number is $SerialNumber"

#Get computer Site Bearer Token
ComputerINFO=$( /usr/bin/curl "$jssBase/JSSResource/computers/serialnumber/$SerialNumber" \
--silent \
--request GET \
--header "Authorization: Bearer $token" )
ComputerSITE=$(echo $ComputerINFO | $xpath '//computer/general/site' | awk -F'<name>|</name>' '{print $2}')
echo "${timestamp} - Pre-flight Check: This Computers Jamf Site is $ComputerSITE"

#Get Deparments from Jamf 
DEPARTMENTS=$( /usr/bin/curl "$jssBase/JSSResource/departments" \
--silent \
--request GET \
--header "Authorization: Bearer $token" )
DEPARTMENTS_ARRAY=$(echo $DEPARTMENTS | xmllint --format --recover - | awk -F'<name>|</name>' '{printf $2"#"}'  | sed 's/####/\n/g' | sed 's/&amp;/\&/g' | tr -d "#" | sort)
echo "${timestamp} - Pre-flight Check: Departments are \n $DEPARTMENTS_ARRAY"

#Get Buildings from Jamf
BUILDINGS=$( /usr/bin/curl -X GET "https://itsemp.jamfcloud.com/JSSResource/buildings" -H "accept: application/xml" -H "Authorization: Bearer $token")
BUILDING_ARRAY=$(echo $BUILDINGS | xmllint --format --recover - | awk -F'<name>|</name>' '{printf $2"#"}'  | sed 's/####/\n/g' | sed 's/&amp;/\&/g' | tr -d "#" | sort )
echo "${timestamp} - Pre-flight Check: Buildings from Jamf $BUILDING_ARRAY"

#list Provisioning Policies
policies=$( /usr/bin/curl "$jssBase/JSSResource/policies/category/$ComputerSITE%20-%20Provisioning" \
--silent \
--request GET \
 --header "Authorization: Bearer $token" )

PolicyID=$(echo $policies | $xpath '//policy/id' | sed 's|[id/<>,]||g' | tr '\n' ' ')
echo "${timestamp} - Pre-flight Check: Provisiong Policy IDs from this computers Site $PolidyID"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Build Setup Your Mac policies to execute 
#   *Read all policies from Jamf for the site this computer is assigned that are in the category 
#   *SITEPREFIX - Provisioning. These policies also need the #Common - Swift Dialog Info - Parameters Only script applied
#   *In that scripts parameters the API will read the Name, Description, Validation, ICON Hash, and Enabled or Disabled
#   *Only Enabled policies will be applied. 
#   *Output JSON to triggerarray="/var/tmp/triggerarray.json"
#   Matt M. 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#Policy ID for #Common - Swift Dialog Info - Parameters Only
swiftDialogpolicyid="531"

#Remove any previous files
rm $triggerarray

#Add Rosetta Install
echo "${timestamp} - Pre-flight Check: Adding Rosetta Install to JSON"
tee $triggerarray << INSTALLS
{
    "steps": [
        {
            "listitem": "Inital Inventory",
            "icon": "90958d0e1f8f8287a86a1198d21cded84eeea44886df2b3357d909fe2e6f1296",
            "progresstext": "A listing of your Macs apps and settings — its inventory — is sent automatically to the Jamf Pro server daily.",
            "trigger_list": [
                {
                    "trigger": "recon",
                    "validation": "None"
                }
            ]
        },
        {
            "listitem": "Rosetta",
            "icon": "8bac19160fabb0c8e7bac97b37b51d2ac8f38b7100b6357642d9505645d37b52",
            "progresstext": "Rosetta enables a Mac with Apple silicon to use apps built for a Mac with an Intel processor.",
            "trigger_list": [
                {
                    "trigger": "commonrosetta2",
                    "validation": "None"

                }
            ]
        },
INSTALLS

#Add all Polcies from this Computers Site that are in the SITEPREFIX - Provisioning category 
declare -a PolicyARRAY=()
#Get Sites,Triggers and Names for each Policy
PolicyCOUNT="0"
PolicyFOUND="0"
for i in $PolicyID; do
    PolicyFOUND=$(($PolicyFOUND+1))
    #Gather information for each policy from Jamf
    policy=$( /usr/bin/curl "$jssBase/JSSResource/policies/id/$i" \
    --silent \
    --request GET \
    --header "Authorization: Bearer $token" )

    #Gather Policy Trigger
    policytrigger=$(echo $policy | $xpath '//policy' | awk -F'<trigger_other>|</trigger_other>' '{print $2}')
    
    #From #Common - Swift Dialog Info - Parameters Only
    policyname=$(echo $policy | $xpath '//scripts/script' | grep "$swiftDialogpolicyid" | awk -F'<parameter4>|</parameter4>' '{print $2}' )
    policydescription=$(echo $policy | $xpath '//scripts/script' | grep "$swiftDialogpolicyid" | awk -F'<parameter5>|</parameter5>' '{print $2}' )
    policyvalidation=$(echo $policy | $xpath '//scripts/script' | grep "$swiftDialogpolicyid" | awk -F'<parameter6>|</parameter6>' '{print $2}' )
    policyicon=$(echo $policy | $xpath '//scripts/script' | grep "$swiftDialogpolicyid" | awk -F'<parameter7>|</parameter7>' '{print $2}' )
    policyenabled=$(echo $policy | $xpath '//scripts/script' | grep "$swiftDialogpolicyid" | awk -F'<parameter8>|</parameter8>' '{print $2}' )


    if [ "$policyenabled" == "Enabled" ]
    then
        echo "${timestamp} - Pre-flight Check: Adding $policyname to JSON"
        tee -a $triggerarray << INSTALLS
        {
            "listitem": "$policyname",
            "icon": "$policyicon",
            "progresstext": "$policydescription",
            "trigger_list": [
                {
                    "trigger": "$policytrigger",
                    "validation": "$policyvalidation"
                }
            ]
        },
INSTALLS
    else
        echo "${timestamp} - Pre-flight Check: Policy was not Enabled"
    fi
done

#Add Final Inventory Run
echo "${timestamp} - Pre-flight Check: Adding final inventory run to JSON"
tee -a $triggerarray << INSTALLS
        {
            "listitem": "Final Inventory",
            "icon": "90958d0e1f8f8287a86a1198d21cded84eeea44886df2b3357d909fe2e6f1296",
            "progresstext": "A listing of your Macs apps and settings — its inventory — is sent automatically to the Jamf Pro server daily.",
            "trigger_list": [
                {
                    "trigger": "recon",
                    "validation": "None"
                }
            ]
        }
    ]
}
INSTALLS

echo "${timestamp} - Pre-flight Check: Expire API token"
#expire the API auth token
/usr/bin/curl "$jssBase/uapi/auth/invalidateToken" \
--silent \
--request POST \
--header "Authorization: Bearer $token"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Create Departments for Welcome JSON
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

departmentsformated=$( mktemp /var/tmp/departmentsformated.XXX)
IFS=$'\n'
for i in $DEPARTMENTS_ARRAY; do
echo "${timestamp} - Pre-flight Check: Found Department $i"
echo "                \"$i\"," >> $departmentsformated
done

departmentsjson=$(cat $departmentsformated)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Create Buildings for Welcome JSON
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

buildingsformated=$( mktemp /var/tmp/buildingsformated.XXX)
IFS=$'\n'
for i in $BUILDING_ARRAY; do
echo "${timestamp} - Pre-flight Check: Found Department $i"
echo "                \"$i\"," >> $buildingsformated
done

buildingsformatedjson=$(cat $buildingsformated)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Validate Operating System Version and Build
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Since swiftDialog requires at least macOS 11 Big Sur, first confirm the major OS version
# shellcheck disable=SC2086 # purposely use single quotes with osascript
if [[ "${osMajorVersion}" -ge 11 ]] ; then

    echo "${timestamp} - Pre-flight Check: macOS ${osMajorVersion} installed; checking build version ..."

    # Confirm the Mac is running `requiredMinimumBuild` (or later)
    if [[ "${osBuild}" > "${requiredMinimumBuild}" ]]; then

        echo "${timestamp} - Pre-flight Check: macOS ${osVersion} (${osBuild}) installed; proceeding ..."

    # When the current `osBuild` is older than `requiredMinimumBuild`; exit with error
    else
        echo "${timestamp} - Pre-flight Check: The installed operating system, macOS ${osVersion} (${osBuild}), needs to be updated to Build ${requiredMinimumBuild}; exiting with error."
        osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\rExpected macOS Build '${requiredMinimumBuild}' (or newer), but found macOS '${osVersion}' ('${osBuild}').\r\r" with title "Setup Your Mac: Detected Outdated Operating System" buttons {"Open Software Update"} with icon caution'
        echo "${timestamp} - Pre-flight Check: Executing /usr/bin/open '${outdatedOsAction}' …"
        su - "${loggedInUser}" -c "/usr/bin/open \"${outdatedOsAction}\""
        exit 1

    fi

# The Mac is running an operating system older than macOS 11 Big Sur; exit with error
else

    echo "${timestamp} - Pre-flight Check: swiftDialog requires at least macOS 11 Big Sur and this Mac is running ${osVersion} (${osBuild}), exiting with error."
    osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\rExpected macOS Build '${requiredMinimumBuild}' (or newer), but found macOS '${osVersion}' ('${osBuild}').\r\r" with title "Setup Your Mac: Detected Outdated Operating System" buttons {"Open Software Update"} with icon caution'
    echo "${timestamp} - Pre-flight Check: Executing /usr/bin/open '${outdatedOsAction}' …"
    su - "${loggedInUser}" -c "/usr/bin/open \"${outdatedOsAction}\""
    exit 1

fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Ensure computer does not go to sleep while running this script (thanks, @grahampugh!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

echo "${timestamp} - Pre-flight Check: Caffeinating this script (PID: $$)"
caffeinate -dimsu -w $$ &



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Validate Setup Assistant has completed
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

while pgrep -q -x "Setup Assistant"; do
    echo "${timestamp} - Pre-flight Check: Setup Assistant is still running; pausing for 2 seconds"
    sleep 2
done

echo "${timestamp} - Pre-flight Check: Setup Assistant is no longer running; proceeding …"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Confirm Dock is running / user is at Desktop
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

until pgrep -q -x "Finder" && pgrep -q -x "Dock"; do
    echo "${timestamp} - Pre-flight Check: Finder & Dock are NOT running; pausing for 1 second"
    sleep 1
done

echo "${timestamp} - Pre-flight Check: Finder & Dock are running; proceeding …"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Validate logged-in user
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

loggedInUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )

if [[ -z "${loggedInUser}" || "${loggedInUser}" == "loginwindow" ]]; then
    echo "${timestamp} - Pre-flight Check: No user logged-in; exiting."
    exit 1
else
    loggedInUserFullname=$( id -F "${loggedInUser}" )
    loggedInUserFirstname=$( echo "$loggedInUserFullname" | cut -d " " -f 1 )
    loggedInUserID=$(id -u "${loggedInUser}")
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Temporarily disable `jamf` binary check-in (thanks, @mactroll and @cube!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then
    echo "${timestamp} - Pre-flight Check: DEBUG MODE: Normally, 'jamf' binary check-in would be temporarily disabled"
else
    echo "${timestamp} - Pre-flight Check: Temporarily disable 'jamf' binary check-in"
    jamflaunchDaemon="/Library/LaunchDaemons/com.jamfsoftware.task.1.plist"
    while [[ ! -f "${jamflaunchDaemon}" ]] ; do
        sleep 0.1
    done
    /bin/launchctl bootout system "$jamflaunchDaemon"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check for / install swiftDialog (Thanks big bunches, @acodega!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogCheck() {

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then echo "${timestamp} - Pre-flight Check: # # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    # Get the URL of the latest PKG From the Dialog GitHub repo
    dialogURL=$(curl --silent --fail "https://api.github.com/repos/bartreardon/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")

    # Expected Team ID of the downloaded PKG
    expectedDialogTeamID="PWA5E9TQ59"

    # Check for Dialog and install if not found
    if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then

        echo "${timestamp} - Pre-flight Check: Dialog not found. Installing..."

        # Create temporary working directory
        workDirectory=$( /usr/bin/basename "$0" )
        tempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$workDirectory.XXXXXX" )

        # Download the installer package
        /usr/bin/curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"

        # Verify the download
        teamID=$(/usr/sbin/spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')

        # Install the package if Team ID validates
        if [[ "$expectedDialogTeamID" == "$teamID" ]]; then

            /usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
            sleep 2
            dialogVersion=$( /usr/local/bin/dialog --version )
            echo "${timestamp} - Pre-flight Check: swiftDialog version ${dialogVersion} installed; proceeding..."

        else

            # Display a so-called "simple" dialog if Team ID fails to validate
            osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "Setup Your Mac: Error" buttons {"Close"} with icon caution'
            completionActionOption="Quit"
            exitCode="1"
            quitScript

        fi

        # Remove the temporary working directory when done
        /bin/rm -Rf "$tempDirectory"

    else

        echo "${timestamp} - Pre-flight Check: swiftDialog version $(dialog --version) found; proceeding..."

    fi

}

if [[ ! -e "/Library/Application Support/Dialog/Dialog.app" ]]; then
    dialogCheck
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Checks Complete
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

echo "${timestamp} - Pre-flight Check: Complete"



####################################################################################################
#
# Dialog Variables
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# infobox-related variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

macOSproductVersion="$( sw_vers -productVersion )"
macOSbuildVersion="$( sw_vers -buildVersion )"
serialNumber=$( system_profiler SPHardwareDataType | grep Serial |  awk '{print $NF}' )
timestamp="$( date '+%Y-%m-%d-%H%M%S' )"
dialogVersion=$( /usr/local/bin/dialog --version )



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Reflect Debug Mode in `infotext` (i.e., bottom, left-hand corner of each dialog)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

case ${debugMode} in
    "true"      ) scriptVersion="DEBUG MODE | Dialog: v${dialogVersion} • Setup Your Mac: v${scriptVersion}" ;;
    "verbose"   ) scriptVersion="VERBOSE DEBUG MODE | Dialog: v${dialogVersion} • Setup Your Mac: v${scriptVersion}" ;;
esac



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Set Dialog path, Command Files, JAMF binary, log files and currently logged-in user
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

dialogApp="/Library/Application\ Support/Dialog/Dialog.app/Contents/MacOS/Dialog"
dialogBinary="/usr/local/bin/dialog"
welcomeCommandFile=$( mktemp /var/tmp/dialogWelcome.XXX )
welcomeCommandFile2=$( mktemp /var/tmp/dialogWelcome2.XXX )
setupYourMacCommandFile=$( mktemp /var/tmp/dialogSetupYourMac.XXX )
failureCommandFile=$( mktemp /var/tmp/dialogFailure.XXX )
jamfBinary="/usr/local/bin/jamf"



####################################################################################################
#
# Welcome dialog
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Welcome" dialog Title, Message and Icon
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

welcomeTitle="Being UVA Provisioning Process."
welcomeMessage="To begin, please enter the required information below, then click **Continue** to start applying settings to your new Mac.  \n\nOnce completed, the **Wait** button will be enabled and you'll be able to review the results before restarting your Mac.  \n\nIf you need assistance, please contact the Help Desk: +1 (801) 555-1212."
welcomeBannerImage="/Library/Application Support/JAMF/UVA Branding/photos/davenport-field.jpeg"
welcomeBannerText="Being UVA Provisioning Process."
welcomeIcon="/Library/Application Support/JAMF/UVA Branding/logos/COMMON-UVA-USER-ICON.png"

# Welcome icon set to either light or dark, based on user's Apperance setting (thanks, @mm2270!)
#appleInterfaceStyle=$( /usr/bin/defaults read /Users/"${loggedInUser}"/Library/Preferences/.GlobalPreferences.plist AppleInterfaceStyle 2>&1 )
#if [[ "${appleInterfaceStyle}" == "Dark" ]]; then
    #welcomeIcon="https://cdn-icons-png.flaticon.com/512/740/740878.png"
#else
    #welcomeIcon="https://cdn-icons-png.flaticon.com/512/979/979585.png"
#fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Welcome" JSON (thanks, @bartreardon!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


welcomeJSON='{
    "bannerimage" : "'"${welcomeBannerImage}"'",
    "bannertext" : "'"${welcomeBannerText}"'",
    "title" : "'"${welcomeTitle}"'",
    "message" : "'"${welcomeMessage}"'",
    "icon" : "'"${welcomeIcon}"'",
    "iconsize" : "198.0",
    "button1text" : "Continue",
    "button2text" : "Quit",
    "infotext" : "'"${scriptVersion}"'",
    "blurscreen" : "true",
    "ontop" : "true",
    "titlefont" : "shadow=true, size=40",
    "messagefont" : "size=16",
    "textfield" : [
        {   "title" : "Comment",
            "required" : false,
            "prompt" : "Enter a comment",
            "editor" : true
        },
        {   "title" : "Computer Name",
            "required" : false,
            "prompt" : "Enter Computer Name"
        },
        {   "title" : "Computer Asset Tag",
            "required" : false,
            "prompt" : "Enter Asset Tag"
        },
        {   "title" : "UVAID",
            "required" : false,
            "prompt" : "Enter UVAID"
        },
        {   "title" : "User Full Name",
            "required" : false,
            "prompt" : "Enter User Full Name"
        },
        {   "title" : "Position",
            "required" : false,
            "prompt" : "Enter Job Title"
        },
        {   "title" : "Room Number",
            "required" : false,
            "prompt" : "Enter Room Number"
        },
        {   "title" : "Phone",
            "required" : false,
            "prompt" : "Work Phone Number"
        }
    ],
  "selectitems" : [
        {   "title" : "Department",
            "default" : "Please select a Department",
            "values" : [
                "Please select a Department",
'$departmentsjson'
                "NONE"
            ]
        },
        {   "title" : "Building",
            "default" : "Please select a Building",
            "values" : [
                "Please select a Building",
'$buildingsformatedjson'
                "NONE"
            ]
        },
        {   "title" : "Usage",
            "default" :"Plese select Device Usage",
            "values" : [
                "Plese select Device Usage",
                "Primary",
	            "Secondary",
                "Spare",
                "Testing",
                "Kiosk",
                "Classroom",
                "Conference Room",
                "Virtual Machine"
            ]
        },
        {   "title" : "Security",
            "default" :"Plese select Security Level",
            "values" : [
                "Plese select Security Level",
                "Moderately Sensitive Data",
                "Highly Sensitive Data"
            ]
        }
    ],
    "height" : "700"
}'



####################################################################################################
#
# Setup Your Mac dialog
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Setup Your Mac" dialog Title, Message, Overlay Icon and Icon
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

title="Setting up your Mac"
message="Please wait while the following apps are installed …"
overlayicon="/Applications/Self Service.app/Contents/Resources/AppIcon.icns"
bannerImage="/Library/Application Support/JAMF/UVA Branding/photos/davenport-field.jpeg"
bannerText="Setting up your Mac"
helpmessage="**Computer Information:** \n\n- **Operating System:**  ${macOSproductVersion} ($macOSbuildVersion)  \n- **Serial Number:** ${serialNumber}  \n- **Dialog:** ${dialogVersion}  \n- **Started:** ${timestamp}"
infobox="Analyzing input …" # Customize at "Update Setup Your Mac's infobox"

# Set initial icon based on whether the Mac is a desktop or laptop
if system_profiler SPPowerDataType | grep -q "Battery Power"; then
    icon="SF=laptopcomputer.and.arrow.down,weight=semibold,colour1=#ef9d51,colour2=#ef7951"
else
    icon="SF=desktopcomputer.and.arrow.down,weight=semibold,colour1=#ef9d51,colour2=#ef7951"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Setup Your Mac" dialog Settings and Features
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

dialogSetupYourMacCMD="$dialogBinary \
--bannerimage \"$bannerImage\" \
--bannertext \"$bannerText\" \
--title \"$title\" \
--message \"$message\" \
--helpmessage \"$helpmessage\" \
--icon \"$icon\" \
--infobox \"${infobox}\" \
--progress \
--progresstext \"Initializing configuration …\" \
--button1text \"Wait\" \
--button1disabled \
--infotext \"$scriptVersion\" \
--titlefont 'shadow=true, size=40' \
--messagefont 'size=14' \
--height '780' \
--position 'centre' \
--blurscreen \
--ontop \
--overlayicon \"$overlayicon\" \
--quitkey k \
--commandfile \"$setupYourMacCommandFile\" "



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Setup Your Mac" policies to execute (Thanks, Obi-@smithjw!)
#
# For each configuration step, specify:
# - listitem: The text to be displayed in the list
# - icon: The hash of the icon to be displayed on the left
#   - See: https://vimeo.com/772998915
# - progresstext: The text to be displayed below the progress bar
# - trigger: The Jamf Pro Policy Custom Event Name
# - validation: [ {absolute path} | Local | Remote | None ]
#   See: https://snelson.us/2023/01/setup-your-mac-validation/
#       - {absolute path} (simulates pre-v1.6.0 behavior, for example: "/Applications/Microsoft Teams.app/Contents/Info.plist")
#       - Local (for validation within this script, for example: "filevault")
#       - Remote (for validation validation via a single-script Jamf Pro policy, for example: "symvGlobalProtect")
#       - None (for triggers which don't require validation, for example: recon; always evaluates as successful)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# The fully qualified domain name of the server which hosts your icons, including any required sub-directories
setupYourMacPolicyArrayIconPrefixUrl="https://ics.services.jamfcloud.com/icon/hash_"

# shellcheck disable=SC1112 # use literal slanted single quotes for typographic reasons
#USE Trigger Array build with API
policy_array=$(<$triggerarray)



####################################################################################################
#
# Failure dialog
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Failure" dialog Title, Message and Icon
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

failureTitle="Failure Detected"
failureMessage="Placeholder message; update in the 'finalise' function"
failureIcon="SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Failure" dialog Settings and Features
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

dialogFailureCMD="$dialogBinary \
--moveable \
--title \"$failureTitle\" \
--message \"$failureMessage\" \
--icon \"$failureIcon\" \
--iconsize 125 \
--width 625 \
--height 525 \
--position topright \
--button1text \"Close\" \
--infotext \"$scriptVersion\" \
--titlefont 'size=22' \
--messagefont 'size=14' \
--overlayicon \"$overlayicon\" \
--commandfile \"$failureCommandFile\" "



#------------------------ With the execption of the `finalise` function, -------------------------#
#------------------------ edits below these line are optional. -----------------------------------#



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Dynamically set `button1text` based on the value of `completionActionOption`
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

case ${completionActionOption} in

    "Shut Down" )
        button1textCompletionActionOption="Shutting Down …"
        progressTextCompletionAction="shut down and "
        ;;

    "Shut Down "* )
        button1textCompletionActionOption="Shut Down"
        progressTextCompletionAction="shut down and "
        ;;

    "Restart" )
        button1textCompletionActionOption="Restarting …"
        progressTextCompletionAction="restart and "
        ;;

    "Restart "* )
        button1textCompletionActionOption="Restart"
        progressTextCompletionAction="restart and "
        ;;

    "Log Out" )
        button1textCompletionActionOption="Logging Out …"
        progressTextCompletionAction="log out and "
        ;;

    "Log Out "* )
        button1textCompletionActionOption="Log Out"
        progressTextCompletionAction="log out and "
        ;;

    "Sleep"* )
        button1textCompletionActionOption="Close"
        progressTextCompletionAction=""
        ;;

    "Quit" )
        button1textCompletionActionOption="Quit"
        progressTextCompletionAction=""
        ;;

    * )
        button1textCompletionActionOption="Close"
        progressTextCompletionAction=""
        ;;

esac



####################################################################################################
#
# Functions
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Client-side Script Logging
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function updateScriptLog() {
    echo -e "$( date +%Y-%m-%d\ %H:%M:%S ) - ${1}" | tee -a "${scriptLog}"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Run command as logged-in user (thanks, @scriptingosx!)
# shellcheck disable=SC2145
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function runAsUser() {

    updateScriptLog "Run \"$@\" as \"$loggedInUserID\" … "
    launchctl asuser "$loggedInUserID" sudo -u "$loggedInUser" "$@"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the "Welcome" dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogUpdateWelcome(){
    updateScriptLog "WELCOME DIALOG: $1"
    echo "$1" >> "$welcomeCommandFile"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the "Setup Your Mac" dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogUpdateSetupYourMac() {
    updateScriptLog "SETUP YOUR MAC DIALOG: $1"
    echo "$1" >> "$setupYourMacCommandFile"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the "Failure" dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogUpdateFailure(){
    updateScriptLog "FAILURE DIALOG: $1"
    echo "$1" >> "$failureCommandFile"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Finalise User Experience
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function finalise(){

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    if [[ "${jamfProPolicyTriggerFailure}" == "failed" ]]; then

        killProcess "caffeinate"
        dialogUpdateSetupYourMac "title: Error, Failure Detected"
        dialogUpdateSetupYourMac "icon: SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"
        dialogUpdateSetupYourMac "progresstext: Failures detected. Please click Continue for troubleshooting information."
        dialogUpdateSetupYourMac "button1text: Continue …"
        dialogUpdateSetupYourMac "button1: enable"
        dialogUpdateSetupYourMac "progress: reset"

        # Wait for user-acknowledgment due to detected failure
        wait

        dialogUpdateSetupYourMac "quit:"
        eval "${dialogFailureCMD}" & sleep 0.3

        updateScriptLog "\n\n# # #\n# FAILURE DIALOG\n# # #\n"
        updateScriptLog "Jamf Pro Policy Name Failures:"
        updateScriptLog "${jamfProPolicyNameFailures}"

        dialogUpdateFailure "message: A failure has been detected, \n\nPlease complete the following steps:\n1. Reboot and login to your Mac  \n2. Login to Self Service  \n3. Re-run any failed policy listed below  \n\nThe following failed:  \n${jamfProPolicyNameFailures}  \n\n\n\nIf you need assistance, please contact the Help Desk,  \n+1 (801) 555-1212, and mention [KB86753099](https://servicenow.company.com/support?id=kb_article_view&sysparm_article=KB86753099#Failures). "
        dialogUpdateFailure "icon: SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"
        dialogUpdateFailure "button1text: ${button1textCompletionActionOption}"

        # Wait for user-acknowledgment due to detected failure
        wait

        dialogUpdateFailure "quit:"
        quitScript "1"

    else

        dialogUpdateSetupYourMac "title: Process Complete."
        dialogUpdateSetupYourMac "icon: SF=checkmark.circle.fill,weight=bold,colour1=#00ff44,colour2=#075c1e"
        dialogUpdateSetupYourMac "progresstext: Process Complete!"
        dialogUpdateSetupYourMac "progress: complete"
        dialogUpdateSetupYourMac "button1text: ${button1textCompletionActionOption}"
        dialogUpdateSetupYourMac "button1: enable"

        # If either "wait" or "sleep" has been specified for `completionActionOption`, honor that behavior
        if [[ "${completionActionOption}" == "wait" ]] || [[ "${completionActionOption}" == "[Ss]leep"* ]]; then
            updateScriptLog "Honoring ${completionActionOption} behavior …"
            eval "${completionActionOption}" "${dialogSetupYourMacProcessID}"
        fi

        quitScript "0"

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse JSON via osascript and JavaScript
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function get_json_value() {
    JSON="$1" osascript -l 'JavaScript' \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env).$2"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse JSON via osascript and JavaScript for the Welcome dialog (thanks, @bartreardon!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function get_json_value_welcomeDialog() {
    for var in "${@:2}"; do jsonkey="${jsonkey}['${var}']"; done
    JSON="$1" osascript -l 'JavaScript' \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env)$jsonkey"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Execute Jamf Pro Policy Custom Events (thanks, @smithjw)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function run_jamf_trigger() {

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    trigger="$1"

    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then

        updateScriptLog "SETUP YOUR MAC DIALOG: DEBUG MODE: TRIGGER: $jamfBinary policy -trigger $trigger"
        if [[ "$trigger" == "recon" ]]; then
            updateScriptLog "SETUP YOUR MAC DIALOG: DEBUG MODE: RECON: $jamfBinary recon ${reconOptions}"
            eval "${jamfBinary} recon ${reconOptions}"
            updateScriptLog "SETUP YOUR MAC DIALOG: DEBUG MODE: DEVICE USAGE: Set to ${deviceusage}"
            updateScriptLog "SETUP YOUR MAC DIALOG: DEBUG MODE: DEVICE USAGE: $jamfBinary policy -trigger ${deviceusagetrigger}"
            eval "${jamfBinary} policy -trigger ${deviceusagetrigger}"
        fi
        sleep 1

    elif [[ "$trigger" == "recon" ]]; then

        dialogUpdateSetupYourMac "listitem: index: $i, status: wait, statustext: Updating …, "
        updateScriptLog "SETUP YOUR MAC DIALOG: Updating computer inventory with the following reconOptions: \"${reconOptions}\" …"
        eval "${jamfBinary} recon ${reconOptions}"
        updateScriptLog "SETUP YOUR MAC DIALOG: DEBUG MODE: DEVICE USAGE: Set to ${deviceusage}"
        updateScriptLog "SETUP YOUR MAC DIALOG: DEBUG MODE: DEVICE USAGE: $jamfBinary policy -trigger ${deviceusagetrigger}"
        eval "${jamfBinary} policy -trigger ${deviceusagetrigger}"

    else

        updateScriptLog "SETUP YOUR MAC DIALOG: RUNNING: $jamfBinary policy -trigger $trigger"
        eval "${jamfBinary} policy -trigger ${trigger}"                                     # Add comment for policy testing
        # eval "${jamfBinary} policy -trigger ${trigger} -verbose | tee -a ${scriptLog}"    # Remove comment for policy testing

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Confirm Policy Execution
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function confirmPolicyExecution() {

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    trigger="${1}"
    validation="${2}"
    updateScriptLog "SETUP YOUR MAC DIALOG: Confirm Policy Execution: '${trigger}' '${validation}'"

    case ${validation} in

        */* ) # If the validation variable contains a forward slash (i.e., "/"), presume it's a path and check if that path exists on disk
            if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then
                updateScriptLog "SETUP YOUR MAC DIALOG: Confirm Policy Execution: DEBUG MODE: Skipping 'run_jamf_trigger ${trigger}'"
                sleep 1
            elif [[ -f "${validation}" ]]; then
                updateScriptLog "SETUP YOUR MAC DIALOG: Confirm Policy Execution: ${validation} exists; skipping 'run_jamf_trigger ${trigger}'"
            else
                updateScriptLog "SETUP YOUR MAC DIALOG: Confirm Policy Execution: ${validation} does NOT exist; executing 'run_jamf_trigger ${trigger}'"
                result=$( "${jamfBinary}" policy -trigger "${trigger}" )
                if [[ "${result}" == *"No policies were found"* ]]; then
                    updateScriptLog "SETUP YOUR MAC DIALOG: Confirm Policy Execution: ${trigger} is not in scope'"
                    noscope="true"
                else
                    updateScriptLog "SETUP YOUR MAC DIALOG: Confirm Policy Execution: ${trigger} is not in scope'"
                    noscope="false"
                fi
            fi
            ;;

        "None" )
            updateScriptLog "SETUP YOUR MAC DIALOG: Confirm Policy Execution: ${validation}"
            if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then
                sleep 1
            else
                run_jamf_trigger "${trigger}"
            fi
            ;;

        * )
            updateScriptLog "SETUP YOUR MAC DIALOG: Confirm Policy Execution Catch-all: ${validation}"
            if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then
                sleep 1
            else
                run_jamf_trigger "${trigger}"
            fi
            ;;

    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Validate Policy Result
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function validatePolicyResult() {

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    trigger="${1}"
    validation="${2}"
    updateScriptLog "SETUP YOUR MAC DIALOG: Validate Policy Result: '${trigger}' '${validation}'"

    case ${validation} in

        ###
        # Absolute Path
        # Simulates pre-v1.6.0 behavior, for example: "/Applications/Microsoft Teams.app/Contents/Info.plist"
        ###

        */* ) 
            updateScriptLog "SETUP YOUR MAC DIALOG: Validate Policy Result: Testing for \"$validation\" …"
            if [[ -f "${validation}" ]]; then
                dialogUpdateSetupYourMac "listitem: index: $i, status: success, statustext: Installed"
            elif [[ "$noscope" = "true" ]]; then
                dialogUpdateSetupYourMac "listitem: index: $i, status: noscope , statustext: Not in scope skipping"
            else
                dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                jamfProPolicyTriggerFailure="failed"
                exitCode="1"
                jamfProPolicyNameFailures+="• $listitem  \n"
            fi
            ;;



        ###
        # Local
        # Validation within this script, for example: "rosetta" or "filevault"
        ###

        "Local" )
            case ${trigger} in
                rosetta ) 
                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Rosetta 2 … " # Thanks, @smithjw!
                    dialogUpdateSetupYourMac "listitem: index: $i, status: wait, statustext: Checking …"
                    arch=$( /usr/bin/arch )
                    if [[ "${arch}" == "arm64" ]]; then
                        # Mac with Apple silicon; check for Rosetta
                        rosettaTest=$( arch -x86_64 /usr/bin/true 2> /dev/null ; echo $? )
                        if [[ "${rosettaTest}" -eq 0 ]]; then
                            # Installed
                            updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Rosetta 2 is installed"
                            dialogUpdateSetupYourMac "listitem: index: $i, status: success, statustext: Running"
                        else
                            # Not Installed
                            updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Rosetta 2 is NOT installed"
                            dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                            jamfProPolicyTriggerFailure="failed"
                            exitCode="1"
                            jamfProPolicyNameFailures+="• $listitem  \n"
                        fi
                    else
                        # Inelligible
                        updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Rosetta 2 is not applicable"
                        dialogUpdateSetupYourMac "listitem: index: $i, status: error, statustext: Inelligible"
                    fi
                    ;;
                filevault )
                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Validate FileVault … "
                    dialogUpdateSetupYourMac "listitem: index: $i, status: wait, statustext: Checking …"
                    updateScriptLog "SETUP YOUR MAC DIALOG: Validate Policy Result: Pausing for 5 seconds for FileVault … "
                    sleep 5 # Arbitrary value; tuning needed
                    if [[ -f /Library/Preferences/com.apple.fdesetup.plist ]]; then
                        fileVaultStatus=$( fdesetup status -extended -verbose 2>&1 )
                        case ${fileVaultStatus} in
                            *"FileVault is On."* ) 
                                updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: FileVault: FileVault is On."
                                dialogUpdateSetupYourMac "listitem: index: $i, status: success, statustext: Enabled"
                                ;;
                            *"Deferred enablement appears to be active for user"* )
                                updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: FileVault: Enabled"
                                dialogUpdateSetupYourMac "listitem: index: $i, status: success, statustext: Enabled (next login)"
                                ;;
                            *  )
                                dialogUpdateSetupYourMac "listitem: index: $i, status: error, statustext: Unknown"
                                jamfProPolicyTriggerFailure="failed"
                                exitCode="1"
                                jamfProPolicyNameFailures+="• $listitem  \n"
                                ;;
                        esac
                    else
                        updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: '/Library/Preferences/com.apple.fdesetup.plist' NOT Found"
                        dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                        jamfProPolicyTriggerFailure="failed"
                        exitCode="1"
                        jamfProPolicyNameFailures+="• $listitem  \n"
                    fi
                    ;;
                sophosEndpointServices )
                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Sophos Endpoint RTS Status … "
                    dialogUpdateSetupYourMac "listitem: index: $i, status: wait, statustext: Checking …"
                    if [[ -d /Applications/Sophos/Sophos\ Endpoint.app ]]; then
                        if [[ -f /Library/Preferences/com.sophos.sav.plist ]]; then
                            sophosOnAccessRunning=$( /usr/bin/defaults read /Library/Preferences/com.sophos.sav.plist OnAccessRunning )
                            case ${sophosOnAccessRunning} in
                                "0" ) 
                                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Sophos Endpoint RTS Status: Disabled"
                                    dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                                    jamfProPolicyTriggerFailure="failed"
                                    exitCode="1"
                                    jamfProPolicyNameFailures+="• $listitem  \n"
                                    ;;
                                "1" )
                                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Sophos Endpoint RTS Status: Enabled"
                                    dialogUpdateSetupYourMac "listitem: index: $i, status: success, statustext: Running"
                                    ;;
                                *  )
                                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Sophos Endpoint RTS Status: Unknown"
                                    dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Unknown"
                                    jamfProPolicyTriggerFailure="failed"
                                    exitCode="1"
                                    jamfProPolicyNameFailures+="• $listitem  \n"
                                    ;;
                            esac
                        else
                            updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Sophos Endpoint Not Found"
                            dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                            jamfProPolicyTriggerFailure="failed"
                            exitCode="1"
                            jamfProPolicyNameFailures+="• $listitem  \n"
                        fi
                    else
                        dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                        jamfProPolicyTriggerFailure="failed"
                        exitCode="1"
                        jamfProPolicyNameFailures+="• $listitem  \n"
                    fi
                    ;;
                globalProtect )
                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Palo Alto Networks GlobalProtect Status … "
                    dialogUpdateSetupYourMac "listitem: index: $i, status: wait, statustext: Checking …"
                    if [[ -d /Applications/GlobalProtect.app ]]; then
                        updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Pausing for 10 seconds to allow Palo Alto Networks GlobalProtect Services … "
                        sleep 10 # Arbitrary value; tuning needed
                        if [[ -f /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist ]]; then
                            globalProtectStatus=$( /usr/libexec/PlistBuddy -c "print :Palo\ Alto\ Networks:GlobalProtect:PanGPS:disable-globalprotect" /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist )
                            case "${globalProtectStatus}" in
                                "0" )
                                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Palo Alto Networks GlobalProtect Status: Enabled"
                                    dialogUpdateSetupYourMac "listitem: index: $i, status: success, statustext: Running"
                                    ;;
                                "1" )
                                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Palo Alto Networks GlobalProtect Status: Disabled"
                                    dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                                    jamfProPolicyTriggerFailure="failed"
                                    exitCode="1"
                                    jamfProPolicyNameFailures+="• $listitem  \n"
                                    ;;
                                *  )
                                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Palo Alto Networks GlobalProtect Status: Unknown"
                                    dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Unknown"
                                    jamfProPolicyTriggerFailure="failed"
                                    exitCode="1"
                                    jamfProPolicyNameFailures+="• $listitem  \n"
                                    ;;
                            esac
                        else
                            updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Result: Palo Alto Networks GlobalProtect Not Found"
                            dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                            jamfProPolicyTriggerFailure="failed"
                            exitCode="1"
                            jamfProPolicyNameFailures+="• $listitem  \n"
                        fi
                    else
                        dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                        jamfProPolicyTriggerFailure="failed"
                        exitCode="1"
                        jamfProPolicyNameFailures+="• $listitem  \n"
                    fi
                    ;;
                * )
                    updateScriptLog "SETUP YOUR MAC DIALOG: Locally Validate Policy Results Local Catch-all: ${validation}"
                    ;;
            esac
            ;;



        ###
        # Remote
        # Validation via a Jamf Pro policy which has a single-script payload, for example: "symvGlobalProtect"
        # See: https://vimeo.com/782561166
        ###

        "Remote" )
            if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then
                updateScriptLog "SETUP YOUR MAC DIALOG: DEBUG MODE: Remotely Confirm Policy Execution: Skipping 'run_jamf_trigger ${trigger}'"
                dialogUpdateSetupYourMac "listitem: index: $i, status: error, statustext: Debug Mode Enabled"
                sleep 0.5
            else
                updateScriptLog "SETUP YOUR MAC DIALOG: Remotely Validate '${trigger}' '${validation}'"
                dialogUpdateSetupYourMac "listitem: index: $i, status: wait, statustext: Checking …"
                result=$( "${jamfBinary}" policy -trigger "${trigger}" )
                if [[ "${result}" == *"Running"* ]]; then
                    dialogUpdateSetupYourMac "listitem: index: $i, status: success, statustext: Running"
                elif [[ "${result}" == *"No policies were found"* ]]; then
                	dialogUpdateSetupYourMac "listitem: index: $i, status: policy not in scope, statustext: Not in Scope - Skipping"
                else
                	dialogUpdateSetupYourMac "listitem: index: $i, status: fail, statustext: Failed"
                    jamfProPolicyTriggerFailure="failed"
                   	exitCode="1"
                   	jamfProPolicyNameFailures+="• $listitem  \n"
                fi
            fi
            ;;



        ###
        # None (always evaluates as successful)
        # For triggers which don't require validation, for example: recon
        ###

        "None" )
            updateScriptLog "SETUP YOUR MAC DIALOG: Confirm Policy Execution: ${validation}"
            dialogUpdateSetupYourMac "listitem: index: $i, status: success, statustext: Installed"
            if [[ "${trigger}" == "recon" ]]; then
                dialogUpdateSetupYourMac "listitem: index: $i, status: wait, statustext: Updating …, "
                updateScriptLog "SETUP YOUR MAC DIALOG: Updating computer inventory with the following reconOptions: \"${reconOptions}\" …"
                if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then
                    updateScriptLog "SETUP YOUR MAC DIALOG: DEBUG MODE: eval ${jamfBinary} recon ${reconOptions}"
                else
                    eval "${jamfBinary} recon ${reconOptions}"
                fi
                dialogUpdateSetupYourMac "listitem: index: $i, status: success, statustext: Updated"
            fi
            ;;



        ###
        # Catch-all
        ###

        * )
            updateScriptLog "SETUP YOUR MAC DIALOG: Validate Policy Results Catch-all: ${validation}"
            dialogUpdateSetupYourMac "listitem: index: $i, status: error, statustext: Error"
            ;;

    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Kill a specified process (thanks, @grahampugh!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function killProcess() {
    process="$1"
    if process_pid=$( pgrep -a "${process}" 2>/dev/null ) ; then
        updateScriptLog "Attempting to terminate the '$process' process …"
        updateScriptLog "(Termination message indicates success.)"
        kill "$process_pid" 2> /dev/null
        if pgrep -a "$process" >/dev/null ; then
            updateScriptLog "ERROR: '$process' could not be terminated."
        fi
    else
        updateScriptLog "The '$process' process isn't running."
    fi
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Completion Action (i.e., Wait, Sleep, Logout, Restart or Shutdown)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function completionAction() {

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then

        # If Debug Mode is enabled, ignore specified `completionActionOption`, display simple dialog box and exit
        runAsUser osascript -e 'display dialog "Setup Your Mac is operating in Debug Mode.\r\r• completionActionOption == '"'${completionActionOption}'"'\r\r" with title "Setup Your Mac: Debug Mode" buttons {"Close"} with icon note'
        exitCode="0"

    else

        shopt -s nocasematch

        case ${completionActionOption} in

            "Shut Down" )
                updateScriptLog "Shut Down sans user interaction"
                killProcess "Self Service"
                # runAsUser osascript -e 'tell app "System Events" to shut down'
                # sleep 5 && runAsUser osascript -e 'tell app "System Events" to shut down' &
                sleep 5 && shutdown -h now &
                ;;

            "Shut Down Attended" )
                updateScriptLog "Shut Down, requiring user-interaction"
                killProcess "Self Service"
                wait
                # runAsUser osascript -e 'tell app "System Events" to shut down'
                # sleep 5 && runAsUser osascript -e 'tell app "System Events" to shut down' &
                sleep 5 && shutdown -h now &
                ;;

            "Shut Down Confirm" )
                updateScriptLog "Shut down, only after macOS time-out or user confirmation"
                runAsUser osascript -e 'tell app "loginwindow" to «event aevtrsdn»'
                ;;

            "Restart" )
                updateScriptLog "Restart sans user interaction"
                killProcess "Self Service"
                # runAsUser osascript -e 'tell app "System Events" to restart'
                # sleep 5 && runAsUser osascript -e 'tell app "System Events" to restart' &
                sleep 5 && shutdown -r now &
                ;;

            "Restart Attended" )
                updateScriptLog "Restart, requiring user-interaction"
                killProcess "Self Service"
                wait
                # runAsUser osascript -e 'tell app "System Events" to restart'
                # sleep 5 && runAsUser osascript -e 'tell app "System Events" to restart' &
                sleep 5 && shutdown -r now &
                ;;

            "Restart Confirm" )
                updateScriptLog "Restart, only after macOS time-out or user confirmation"
                runAsUser osascript -e 'tell app "loginwindow" to «event aevtrrst»'
                ;;

            "Log Out" )
                updateScriptLog "Log out sans user interaction"
                killProcess "Self Service"
                # sleep 5 && runAsUser osascript -e 'tell app "loginwindow" to «event aevtrlgo»'
                # sleep 5 && runAsUser osascript -e 'tell app "loginwindow" to «event aevtrlgo»' &
                sleep 5 && launchctl bootout user/"${loggedInUserID}"
                ;;

            "Log Out Attended" )
                updateScriptLog "Log out sans user interaction"
                killProcess "Self Service"
                wait
                # sleep 5 && runAsUser osascript -e 'tell app "loginwindow" to «event aevtrlgo»'
                # sleep 5 && runAsUser osascript -e 'tell app "loginwindow" to «event aevtrlgo»' &
                sleep 5 && launchctl bootout user/"${loggedInUserID}"
                ;;

            "Log Out Confirm" )
                updateScriptLog "Log out, only after macOS time-out or user confirmation"
                sleep 5 && runAsUser osascript -e 'tell app "System Events" to log out'
                ;;

            "Sleep"* )
                sleepDuration=$( awk '{print $NF}' <<< "${1}" )
                updateScriptLog "Sleeping for ${sleepDuration} seconds …"
                sleep "${sleepDuration}"
                killProcess "Dialog"
                updateScriptLog "Goodnight!"
                ;;

            "Quit" )
                updateScriptLog "Quitting script"
                exitCode="0"
                ;;

            * )
                updateScriptLog "Using the default of 'wait'"
                wait
                ;;

        esac

        shopt -u nocasematch

    fi

    exit "${exitCode}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Quit Script (thanks, @bartreadon!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function quitScript() {

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    updateScriptLog "QUIT SCRIPT: Exiting …"

    # Stop `caffeinate` process
    updateScriptLog "QUIT SCRIPT: De-caffeinate …"
    killProcess "caffeinate"

    # Reenable 'jamf' binary check-in
    # Purposely commented-out on 2023-01-26-092705; presumes Mac will be rebooted
    # updateScriptLog "QUIT SCRIPT: Reenable 'jamf' binary check-in"
    # launchctl bootstrap system "${jamflaunchDaemon}"

    # Remove welcomeCommandFile
    if [[ -e ${welcomeCommandFile} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${welcomeCommandFile} …"
        rm "${welcomeCommandFile}"
    fi

    # Remove setupYourMacCommandFile
    if [[ -e ${setupYourMacCommandFile} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${setupYourMacCommandFile} …"
        rm "${setupYourMacCommandFile}"
    fi

    # Remove failureCommandFile
    if [[ -e ${failureCommandFile} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${failureCommandFile} …"
        rm "${failureCommandFile}"
    fi

    # Remove any default dialog file
    if [[ -e /var/tmp/dialog.log ]]; then
        updateScriptLog "QUIT SCRIPT: Removing default dialog file …"
        rm /var/tmp/dialog.log
    fi

    # Check for user clicking "Quit" at Welcome dialog
    if [[ "${welcomeReturnCode}" == "2" ]]; then
        exitCode="1"
        exit "${exitCode}"
    else
        updateScriptLog "QUIT SCRIPT: Executing Completion Action Option: '${completionActionOption}' …"
        completionAction "${completionActionOption}"
    fi

}



####################################################################################################
#
# Program
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Client-side Logging
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ ! -f "${scriptLog}" ]]; then
    touch "${scriptLog}"
    updateScriptLog "*** Created log file via script ***"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Debug Mode Logging Notification
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then
    updateScriptLog "\n\n###\n# ${scriptVersion}\n###\n"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# If Debug Mode is enabled, replace `blurscreen` with `movable`
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then
    welcomeJSON=${welcomeJSON//blurscreen/moveable}
    dialogSetupYourMacCMD=${dialogSetupYourMacCMD//blurscreen/moveable}
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Write Welcome JSON to disk
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

echo "$welcomeJSON" > "$welcomeCommandFile"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Display Welcome dialog and capture user's input
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${welcomeDialog}" == "true" ]]; then
    output="/var/tmp/Welcomeoutput.txt"
    rm $output

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi
    rm $output
    #welcomeResults=$( eval "${dialogApp} --jsonfile ${welcomeCommandFile} --json" )
    welcomeResults=$( eval "${dialogApp} --jsonfile ${welcomeCommandFile}" )
    
    #Output Results to file 
    echo "$welcomeResults" > $output
    

    if [[ -z "${welcomeResults}" ]]; then
        welcomeReturnCode="2"
    else
        welcomeReturnCode="0"
    fi

    case "${welcomeReturnCode}" in

        0)  # Process exit code 0 scenario here
            updateScriptLog "WELCOME DIALOG: ${loggedInUser} entered information and clicked Continue"

            ###
            # Extract the various values from the welcomeResults JSON
            ###

            #comment=$(get_json_value_welcomeDialog "$welcomeResults" "Comment")
            #computerName=$(get_json_value_welcomeDialog "$welcomeResults" "Computer Name")
            #userName=$(get_json_value_welcomeDialog "$welcomeResults" "User Name")
            #assetTag=$(get_json_value_welcomeDialog "$welcomeResults" "Asset Tag")
            #department=$(get_json_value_welcomeDialog "$welcomeResults" ""Department"" ""selectedValue"" )
            #building=$(get_json_value_welcomeDialog "$welcomeResults" "Building"  "selectedValue" )
            #deviceusage=$(get_json_value_welcomeDialog "$welcomeResults" "Usage" "selectedValue" )
            #securitylevel=$(get_json_value_welcomeDialog "$welcomeResults" ""Security"" "selectedValue" )

            #Text Boxes
            comment=$( cat $output | grep -m 1 "Comment" | awk -F " : " '{print $NF}' )
            computerName=$( cat $output | grep -m 1 "Computer Name" | awk -F " : " '{print $NF}' )
            userName=$( cat $output | grep -m 1 "UVAID" | awk -F " : " '{print $NF}' )
            userFullName=$( cat $output | grep "User Full Name" | awk -F " : " '{print $NF}' )
            position=$( cat $output | grep "Position" | awk -F " : " '{print $NF}' )
            phone=$( cat $output | grep "Phone" | awk -F " : " '{print $NF}' )
            assetTag=$( cat $output | grep -m 1 "Computer Asset Tag" | awk -F " : " '{print $NF}' )
            room=$( cat $output | grep -m 1 "Room Number" | awk -F " : " '{print $NF}' )
            

            #Dropdown Boxes
            department=$( cat $output | grep -m 1 "Department" | awk -F " : " '{print $NF}' | sed 's/"//g' )
            building=$( cat $output | grep -m 1 "Building" | awk -F " : " '{print $NF}' | sed 's/"//g' )
            deviceusage=$( cat $output | grep -m 1 "Usage" | awk -F " : " '{print $NF}' | sed 's/"//g' )
            security=$( cat $output | grep -m 1 "Security" | awk -F " : " '{print $NF}' | sed 's/"//g' )

            ###
            # Output the various values from the welcomeResults JSON to the log file
            ###

            updateScriptLog "WELCOME DIALOG: • Comment: $comment"
            updateScriptLog "WELCOME DIALOG: • Computer Name: $computerName"
            updateScriptLog "WELCOME DIALOG: • User Name: $userName"
            updateScriptLog "WELCOME DIALOG: • User Full Name: $userFullName"
            updateScriptLog "WELCOME DIALOG: • Job Title: $position"
            updateScriptLog "WELCOME DIALOG: • Phone: $phone"
            updateScriptLog "WELCOME DIALOG: • Asset Tag: $assetTag"
            updateScriptLog "WELCOME DIALOG: • Room Number: $room"
            updateScriptLog "WELCOME DIALOG: • Department: $department"
            updateScriptLog "WELCOME DIALOG: • Buildingt: $building"
            updateScriptLog "WELCOME DIALOG: • Usage: $deviceusage"
            updateScriptLog "WELCOME DIALOG: • Security: $security"


            ###
            # Evaluate Various User Input
            ###

            # Computer Name
            if [[ -n "${computerName}" ]]; then

                # UNTESTED, UNSUPPORTED "YOYO" EXAMPLE
                updateScriptLog "WELCOME DIALOG: Set Computer Name …"
                currentComputerName=$( scutil --get ComputerName )
                currentLocalHostName=$( scutil --get LocalHostName )

                # Sets LocalHostName to a maximum of 15 characters, comprised of first eight characters of the computer's
                # serial number and the last six characters of the client's MAC address
                firstEightSerialNumber=$( system_profiler SPHardwareDataType | awk '/Serial\ Number\ \(system\)/ {print $NF}' | cut -c 1-8 )
                lastSixMAC=$( ifconfig en0 | awk '/ether/ {print $2}' | sed 's/://g' | cut -c 7-12 )
                newLocalHostName=${firstEightSerialNumber}-${lastSixMAC}

                if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]] ; then

                    updateScriptLog "WELCOME DIALOG: DEBUG MODE: Would have renamed computer from: \"${currentComputerName}\" to \"${computerName}\" "
                    updateScriptLog "WELCOME DIALOG: DEBUG MODE: Would have renamed LocalHostName from: \"${currentLocalHostName}\" to \"${newLocalHostName}\" "

                else

                    # Set the Computer Name to the user-entered value
                    scutil --set ComputerName "${computerName}"

                    # Set the LocalHostName to `newLocalHostName`
                    scutil --set LocalHostName "${newLocalHostName}"

                    # Delay required to reflect change …
                    # … side-effect is a delay in the "Setup Your Mac" dialog appearing
                    sleep 5
                    updateScriptLog "WELCOME DIALOG: Renamed computer from: \"${currentComputerName}\" to \"$( scutil --get ComputerName )\" "
                    updateScriptLog "WELCOME DIALOG: Renamed LocalHostName from: \"${currentLocalHostName}\" to \"$( scutil --get LocalHostName )\" "

                fi

            else

                updateScriptLog "WELCOME DIALOG: ${loggedInUser} did NOT specify a new computer name"
                updateScriptLog "WELCOME DIALOG: • Current Computer Name: \"$( scutil --get ComputerName )\" "
                updateScriptLog "WELCOME DIALOG: • Current Local Host Name: \"$( scutil --get LocalHostName )\" "

            fi
            #Upload Comment as Attachemtn in Jamf Inventory
            if [[ -n "${comment}" ]]; then
                
                #Write Comment to file
                commentfile="/var/tmp/$filetime-Provisioning-Comment.txt"
                rm $output
                echo "$comment" > $commentfile

                #Upload File to Jamf 
                #created base64-encoded credentials
                encodedCredentials=$( printf "$apiUser:$apiPass" | /usr/bin/iconv -t ISO-8859-1 | /usr/bin/base64 -i - )

                # generate an auth token
                authToken=$( /usr/bin/curl "$jssBase/uapi/auth/tokens" \
                --silent \
                --request POST \
                --header "Authorization: Basic $encodedCredentials" )

                #parse authToken for token, omit expiration
                token=$( /usr/bin/awk -F \" '{ print $4 }' <<< "$authToken" | /usr/bin/xargs )

                #Post File to Jamf
                computerName=$(/usr/sbin/scutil --get ComputerName)
                /usr/bin/curl "$jssBase/JSSResource/fileuploads/computers/name/${computerName}" \
                --silent \
                --request POST \
                --form name=@$commentfile \
                --header "Authorization: Bearer $token" 

                #expire the API auth token
                /usr/bin/curl "$jssBase/uapi/auth/invalidateToken" \
                --silent \
                --request POST \
                --header "Authorization: Bearer $token"
            fi

            # User Name
            if [[ -n "${userName}" ]]; then
                # UNTESTED, UNSUPPORTED "YOYO" EXAMPLE
                reconOptions+="-endUsername \"${userName}\" "
            fi
            
            # Email 
            if [[ -n "${userName}" ]]; then
                # UNTESTED, UNSUPPORTED "YOYO" EXAMPLE
                reconOptions+="-emil \"${userName}@virginia.edu\" "
            fi

            #Phone
            if [[ -n "${phone}" ]]; then
                # UNTESTED, UNSUPPORTED "YOYO" EXAMPLE
                reconOptions+="-phone \"${phone}\" "
            fi

            # User Full Name
            if [[ -n "${userFullName}" ]]; then
                # UNTESTED, UNSUPPORTED "YOYO" EXAMPLE
                reconOptions+="-realname  \"${userFullName}\" "
            fi
            
            # Position
            if [[ -n "${position}" ]]; then
                # UNTESTED, UNSUPPORTED "YOYO" EXAMPLE
                reconOptions+="-position \"${position}\" "
            fi

            # Asset Tag
            if [[ -n "${assetTag}" ]]; then
                reconOptions+="-assetTag \"${assetTag}\" "
            fi

            # Department
            if [[ -n "${department}" ]]; then
                # UNTESTED, UNSUPPORTED "YOYO" EXAMPLE
                reconOptions+="-department \"${department}\" "
            fi

            # Building
            if [[ -n "${building}" ]]; then
                # UNTESTED, UNSUPPORTED "YOYO" EXAMPLE
                reconOptions+="-building \"${building}\" "
            fi
            
            # Room
            if [[ -n "${room}" ]]; then
                # UNTESTED, UNSUPPORTED "YOYO" EXAMPLE
                reconOptions+="-room \"${room}\" "
            fi
            

            # Output `recon` options to log
            updateScriptLog "WELCOME DIALOG: reconOptions: ${reconOptions}"

            ###
            # Device Usage
            ###
            if [[ -n "${deviceusage}" ]]; then
                #Device Usage Triggers
                if [ "${deviceusage}" = "Primary" ]; then
	                updateScriptLog "WELCOME DIALOG: Device Usage is : ${deviceusage}"
                    deviceusagetrigger="commoncausageprimary"
                    updateScriptLog "WELCOME DIALOG: Setting Device Usage Tirgger to : ${deviceusagetrigger}"
                else
	                echo "Device is not Primary"
                fi
                if [ "${deviceusage}" = "Secondary" ]; then
	                updateScriptLog "WELCOME DIALOG: Device Usage is : ${deviceusage}"
                    deviceusagetrigger="commoncausagesecondary"
                    updateScriptLog "WELCOME DIALOG: Setting Device Usage Tirgger to : ${deviceusagetrigger}"
                else
	                echo "Device is not Secondary"
                fi
                if [ "${deviceusage}" = "Spare" ]; then
	                updateScriptLog "WELCOME DIALOG: Device Usage is : ${deviceusage}"
                    deviceusagetrigger="commoncausagespare"
                    updateScriptLog "WELCOME DIALOG: Setting Device Usage Tirgger to : ${deviceusagetrigger}"
                else
	                echo "Device is not Spare"
                fi
                if [ "${deviceusage}" = "Testing" ]; then
	                updateScriptLog "WELCOME DIALOG: Device Usage is : ${deviceusage}"
                    deviceusagetrigger="commoncausagetesting"
                    updateScriptLog "WELCOME DIALOG: Setting Device Usage Tirgger to : ${deviceusagetrigger}"
                else
	                echo "Device is not Testing"
                fi
                if [ "${deviceusage}" = "Kiosk" ]; then
	                updateScriptLog "WELCOME DIALOG: Device Usage is : ${deviceusage}"
                    deviceusagetrigger="commoncausagekiosk"
                    updateScriptLog "WELCOME DIALOG: Setting Device Usage Tirgger to : ${deviceusagetrigger}"
                else
	                echo "Device is not Kiosk"
                fi
                if [ "${deviceusage}" = "Classroom" ]; then
	                updateScriptLog "WELCOME DIALOG: Device Usage is : ${deviceusage}"
                    deviceusagetrigger="commoncausageclassroom"
                    updateScriptLog "WELCOME DIALOG: Setting Device Usage Tirgger to : ${deviceusagetrigger}"
                else
	                echo "Device is not Classroom"
                fi
                if [ "${deviceusage}" = "Conference Room" ]; then
	                updateScriptLog "WELCOME DIALOG: Device Usage is : ${deviceusage}"
                    deviceusagetrigger="commoncausageconferenceroom"
                    updateScriptLog "WELCOME DIALOG: Setting Device Usage Tirgger to : ${deviceusagetrigger}"
                else
	                echo "Device is not Conference Room"
                fi
                if [ "${deviceusage}" = "Virtual Machine" ]; then
	                updateScriptLog "WELCOME DIALOG: Device Usage is : ${deviceusage}"
                    deviceusagetrigger="commoncausagevm"
                    updateScriptLog "WELCOME DIALOG: Setting Device Usage Tirgger to : ${deviceusagetrigger}"
                else
	                echo "Device is not Virtual Machine"
                fi
            fi

            ###
            # Display "Setup Your Mac" dialog (and capture Process ID)
            ###

            eval "${dialogSetupYourMacCMD[*]}" & sleep 0.3
            dialogSetupYourMacProcessID=$!
            until pgrep -q -x "Dialog"; do
                updateScriptLog "WELCOME DIALOG: Waiting to display 'Setup Your Mac' dialog; pausing"
                sleep 0.5
            done
            updateScriptLog "WELCOME DIALOG: 'Setup Your Mac' dialog displayed; ensure it's the front-most app"
            runAsUser osascript -e 'tell application "Dialog" to activate'
            ;;

        2)  # Process exit code 2 scenario here
            updateScriptLog "WELCOME DIALOG: ${loggedInUser} clicked Quit at Welcome dialog"
            completionActionOption="Quit"
            quitScript "1"
            ;;

        3)  # Process exit code 3 scenario here
            updateScriptLog "WELCOME DIALOG: ${loggedInUser} clicked infobutton"
            osascript -e "set Volume 3"
            afplay /System/Library/Sounds/Glass.aiff
            ;;

        4)  # Process exit code 4 scenario here
            updateScriptLog "WELCOME DIALOG: ${loggedInUser} allowed timer to expire"
            quitScript "1"
            ;;

        *)  # Catch all processing
            updateScriptLog "WELCOME DIALOG: Something else happened; Exit code: ${welcomeReturnCode}"
            quitScript "1"
            ;;

    esac

else

    ###
    # Display "Setup Your Mac" dialog (and capture Process ID)
    ###

    eval "${dialogSetupYourMacCMD[*]}" & sleep 0.3
    dialogSetupYourMacProcessID=$!
    until pgrep -q -x "Dialog"; do
        updateScriptLog "WELCOME DIALOG: Waiting to display 'Setup Your Mac' dialog; pausing"
        sleep 0.5
    done
    updateScriptLog "WELCOME DIALOG: 'Setup Your Mac' dialog displayed; ensure it's the front-most app"
    runAsUser osascript -e 'tell application "Dialog" to activate'

fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Iterate through policy_array JSON to construct the list for swiftDialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `verbose` Debug Mode
if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

dialog_step_length=$(get_json_value "${policy_array[*]}" "steps.length")
for (( i=0; i<dialog_step_length; i++ )); do
    listitem=$(get_json_value "${policy_array[*]}" "steps[$i].listitem")
    list_item_array+=("$listitem")
    icon=$(get_json_value "${policy_array[*]}" "steps[$i].icon")
    icon_url_array+=("$icon")
done



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Determine the "progress: increment" value based on the number of steps in policy_array
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `verbose` Debug Mode
if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

totalProgressSteps=$(get_json_value "${policy_array[*]}" "steps.length")
progressIncrementValue=$(( 100 / totalProgressSteps ))
updateScriptLog "SETUP YOUR MAC DIALOG: Total Number of Steps: ${totalProgressSteps}"
updateScriptLog "SETUP YOUR MAC DIALOG: Progress Increment Value: ${progressIncrementValue}"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# The ${array_name[*]/%/,} expansion will combine all items within the array adding a "," character at the end
# To add a character to the start, use "/#/" instead of the "/%/"
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `verbose` Debug Mode
if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

list_item_string=${list_item_array[*]/%/,}
dialogUpdateSetupYourMac "list: ${list_item_string%?}"
for (( i=0; i<dialog_step_length; i++ )); do
    dialogUpdateSetupYourMac "listitem: index: $i, icon: ${setupYourMacPolicyArrayIconPrefixUrl}${icon_url_array[$i]}, status: pending, statustext: Pending …"
done
dialogUpdateSetupYourMac "list: show"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Set initial progress bar
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `verbose` Debug Mode
if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

updateScriptLog "SETUP YOUR MAC DIALOG: Initial progress bar"
dialogUpdateSetupYourMac "progress: 1"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Close Welcome dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `verbose` Debug Mode
if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

dialogUpdateWelcome "quit:"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update Setup Your Mac's infobox
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `verbose` Debug Mode
if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

infobox=""

if [[ -n ${computerName} ]]; then infobox+="**Computer Name:**  \n$computerName  \n\n" ; fi
if [[ -n ${userName} ]]; then infobox+="**UVAID:**  \n$userName  \n\n" ; fi
if [[ -n ${userFullName} ]]; then infobox+="**Full Name:**  \n$userFullName  \n\n" ; fi
if [[ -n ${assetTag} ]]; then infobox+="**Asset Tag:**  \n$assetTag  \n\n" ; fi
if [[ -n ${department} ]]; then infobox+="**Department:**  \n$department  \n\n" ; fi
if [[ -n ${building} ]]; then infobox+="**Building:**  \n$building  \n\n" ; fi
if [[ -n ${room} ]]; then infobox+="**Room Number:**  \n$room \n\n" ; fi
if [[ -n ${deviceusage} ]]; then infobox+="**Usage:**  \n$deviceusage  \n\n" ; fi
if [[ -n ${securitylevel} ]]; then infobox+="**Security**  \n$security  \n\n" ; fi

dialogUpdateSetupYourMac "infobox: ${infobox}"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# This for loop will iterate over each distinct step in the policy_array array
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

for (( i=0; i<dialog_step_length; i++ )); do 

    # Output Line Number in `verbose` Debug Mode
    if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    # Initialize SECONDS
    SECONDS="0"

    # Creating initial variables
    listitem=$(get_json_value "${policy_array[*]}" "steps[$i].listitem")
    icon=$(get_json_value "${policy_array[*]}" "steps[$i].icon")
    progresstext=$(get_json_value "${policy_array[*]}" "steps[$i].progresstext")
    trigger_list_length=$(get_json_value "${policy_array[*]}" "steps[$i].trigger_list.length")

    # If there's a value in the variable, update running swiftDialog
    if [[ -n "$listitem" ]]; then
        updateScriptLog "\n\n# # #\n# SETUP YOUR MAC DIALOG: policy_array > listitem: ${listitem}\n# # #\n"
        dialogUpdateSetupYourMac "listitem: index: $i, status: wait, statustext: Installing …, "
    fi
    if [[ -n "$icon" ]]; then dialogUpdateSetupYourMac "icon: ${setupYourMacPolicyArrayIconPrefixUrl}${icon}"; fi
    if [[ -n "$progresstext" ]]; then dialogUpdateSetupYourMac "progresstext: $progresstext"; fi
    if [[ -n "$trigger_list_length" ]]; then

        for (( j=0; j<trigger_list_length; j++ )); do

            # Setting variables within the trigger_list
            trigger=$(get_json_value "${policy_array[*]}" "steps[$i].trigger_list[$j].trigger")
            validation=$(get_json_value "${policy_array[*]}" "steps[$i].trigger_list[$j].validation")
            case ${validation} in
                "Local" | "Remote" )
                    updateScriptLog "SETUP YOUR MAC DIALOG: Skipping Policy Execution due to '${validation}' validation"
                    ;;
                * )
                    confirmPolicyExecution "${trigger}" "${validation}"
                    ;;
            esac

        done

    fi

    validatePolicyResult "${trigger}" "${validation}"

    # Increment the progress bar
    dialogUpdateSetupYourMac "progress: increment ${progressIncrementValue}"

    # Record duration
    updateScriptLog "SETUP YOUR MAC DIALOG: Elapsed Time: $(printf '%dh:%dm:%ds\n' $((SECONDS/3600)) $((SECONDS%3600/60)) $((SECONDS%60)))"

done



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Complete processing and enable the "Done" button
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `verbose` Debug Mode
if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi

finalise