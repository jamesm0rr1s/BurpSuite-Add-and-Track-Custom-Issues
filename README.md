# Add & Track Custom Issues

This extension allows custom scan issues to be added and tracked within Burp. Burp adds issues that it finds from active and passive scans, but does not allow custom issues to be created or tracked. Custom issues can now be created from different tabs within Burp by right clicking and selecting "Add & Track Custom Issue". The recommended place to create a custom issue from, is within the Target tab:
 - Select a target to create a custom scan issue for.
 - Right click in the Site Map, Contents, or Issues section to display the context menu.
 - From the context menu, select "Add & Track Custom Issue".
 - Information will automatically be filled in including the protocol, host, port, path, request, and response.
 - The issue name, severity, confidence, issue detail, issue background, remediation detail, and remediation background can then be filled in.
 - The Issue Selection tab allows predefined issues to quickly be selected, which will populate the issue name, severity, confidence, issue detail, issue background, remediation detail, and remediation background.
 - If selecting a predefined issue, it is recommended to update the Issue Detail and to add information to the Remediation Detail that ties the new issue to the predefined Issue Background and Remediation Background.
 - Once all of the needed information is filled in, click the "Add & Track Custom Issue" button to add the custom issue to the scan issues.
 - Each new issue that is added to the scan issues, will also be added to the issue selection table. This table can be exported to CSV or JSON formats, and can later be imported for future scans.
 - Issues can also be added from the extension's main tab. If there is not an issue selected from the issue table, a new blank issue can be created. If an issue is selected from the issue table, a new issue based off of the selected issue can be created.


## Requirements:
This extension requires Burp Suite Professional and Jython standalone.


## Main features include:
 - Add custom scan issues.
 - Track custom scan issues.
 - Delete custom scan issues.
 - Export custom scan issues to CSV and JSON formats for future scans.
 - Import previously created custom scan issues from CSV and JSON formats.


## Other features that have been added include:
 - If a new issue is added from the menu option, then the protocol, host, port, path, request, and response will be filled in automatically.
 - Warning labels will appear if the scan issues table has been updated since the last export, to help users remember to save their custom scan issues in case they need them for future scans.
 - The tab key transfers focus to the next text field instead of inserting a tab into the text field.
 - Disabled text fields have a darker background color.
 - Press Ctrl+Z to undo an action.
 - Press Ctrl+Shift+Z to redo an action.
 - Press Ctrl+Y to redo an action.
 - The custom issues table can be sorted and unsorted.
 - Rows in the custom issue table can be unselected.
 - If a new issue is created from the extension's main tab, the popup dialog will be cleared if it is not already visible.
 - If the popup dialog is visible, then the issue information will be added and the rest of the panel will not be cleared, since it may contain data that was already entered for the new issue.
 - A red border will be added to any required fields that are left blank when trying to add an issue.
 - The port field has to contain a valid port.
 - The host and path fields cannot contain a space.
 - The issue name field cannot start with a space.
 - Changing the protocol dropdown will set the port for the user, but the port can still be changed manually if needed.
 - If the host field starts with http:// or https:// it will be removed because the protocol dropdown sets the protocol.
 - If the host field ends in a forward slash '/' it will be removed because one is added after the port by default.
 - If the path field does not start with a forward slash '/' one will be added.


## License
[MIT License](LICENSE)