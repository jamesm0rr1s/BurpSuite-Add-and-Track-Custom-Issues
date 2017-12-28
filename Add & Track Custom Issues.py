from burp import IBurpExtender # for the extension
from burp import IContextMenuFactory # for adding an option to the right click popup menu
from burp import IHttpRequestResponse # for custom IHttpRequestResponse
from burp import IHttpService # for custom IHttpService
from burp import IScanIssue # for adding a new issue
from burp import ITab # for creating an extension tab
from java.awt import BorderLayout # for panel layouts
from java.awt import Color # for setting a darker background on disabled text areas
from java.awt import Font # for adding bold font to red text labels in main tab
from java.awt import GridBagConstraints # for panel layouts alignment
from java.awt import GridBagLayout # for panel layouts
from java.awt import GridLayout # for button layout in main tab
from java.awt import Insets # for panel layouts spacing
from java.awt.event import ActionListener # for custom action listener for protocol combo box
from java.awt.event import InputEvent # for undo and redo in text areas
from java.awt.event import KeyEvent # for allowing tab key to change focus instead of inserting tab into text areas
from java.awt.event import MouseListener # for detecting mouse clicks on tables so row doesn't flash when dragging a clicked mouse
from java.lang import Integer # for filter on port text area
from java.lang import StringBuilder # for filter on port text area
from java.net import URL # for creating URLs
from javax.swing import AbstractAction # for undo and redo in text areas
from javax.swing import Action # for undo and redo in text areas
from javax.swing import BorderFactory # for panel borders
from javax.swing import JButton # for buttons
from javax.swing import JComboBox # for severity, confidence, and protocol combo boxes
from javax.swing import JDialog # for main popup dialog box
from javax.swing import JFileChooser # for importing and exporting dialog boxes
from javax.swing import JFrame # for importing and exporting dialog boxes
from javax.swing import JLabel # for labels
from javax.swing import JMenuItem # for adding menu choices to add a new issue
from javax.swing import JOptionPane # for import and export message boxes
from javax.swing import JPanel # for panels
from javax.swing import JScrollPane # for scroll panes to help with extended text areas
from javax.swing import JSplitPane # for split panes in issue selection popup dialog tab and main tab
from javax.swing import JTabbedPane # for tabbed pane in popup dialog
from javax.swing import JTable # for tables in issue selection popup dialog tab and main tab
from javax.swing import JTextArea # for text areas in popup dialog and main panel
from javax.swing import JTextPane # for centering text in disabled issue name and severity text panes
from javax.swing import KeyStroke # for undo and redo in text areas
from javax.swing import ListSelectionModel # for only allowing single row selection
from javax.swing import SortOrder # for setting table sort order ascending descending unsorted
from javax.swing import SwingConstants # for Swing constants
from javax.swing.border import TitledBorder # for panel borders
from javax.swing.event import DocumentListener # for detecting changes to text areas to update the issue location
from javax.swing.event import UndoableEditListener # for undo and redo in text areas
from javax.swing.filechooser import FileNameExtensionFilter # for importing and exporting
from javax.swing.table import DefaultTableModel # for creating shared a custom table model
from javax.swing.table import TableRowSorter # for setting table sort order ascending descending unsorted
from javax.swing.text import DocumentFilter # for applying filters on the issue name, host, and port text areas
from javax.swing.text import SimpleAttributeSet # for centering text in disabled issue name and severity text panes
from javax.swing.text import StyleConstants # for centering text in disabled issue name and severity text panes
from javax.swing.undo import UndoManager # for undo and redo in text areas
import csv # for importing and exporting to and from csv
import json # for importing and exporting to and from json
import os # for splitting the file name and file extension when importing and exporting


#
# Burp extender main class
#

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

	#
	# implement IBurpExtender when the extension is loaded
	#

	def registerExtenderCallbacks(self, callbacks):

		# keep reference to callbacks object
		self._callbacks = callbacks

		# obtain extension helpers object
		self._helpers = callbacks.getHelpers()

		# set the extension name
		self._EXTENSION_NAME = "Add & Track Custom Issues"

		# set the extension version
		self._EXTENSION_VERSION = "1.0"

		# set names for the tabs
		self._MAIN_TAB_NAME = "Main"
		self._DIALOG_TAB_1_NAME = "New Issue"
		self._DIALOG_TAB_2_NAME = "Issue Selection"

		# create the button names for the main tab
		self._MAIN_TAB_BUTTON_NAMES = ["Add Issue", "Export Issues To CSV", "Import Issues From CSV", "Delete Issue", "Export Issues To JSON", "Import Issues From JSON"]

		# create a consistent background color for disabled text areas and text panes
		self._DISABLED_BACKGROUND_COLOR = Color(224, 225, 226)

		# set warning message text for when the table has been updated and not exported yet
		self._WARNING_MESSAGE_TABLE_UPDATED = "*** WARNING: The table has been updated since the last export. ***"

		# set html text for text panes
		self._HTML_FOR_TEXT_PANES = ["<html><body style='background-color:#e2e3e4; text-align:center; padding-top:3px; padding-bottom:3px;'>", "</body></html>"]

		# create choices for the combo boxes
		self._SEVERITY_COMBOBOX_CHOICES = ["High", "Medium", "Low", "Information"]
		self._CONFIDENCE_COMBOBOX_CHOICES = ["Certain", "Firm", "Tentative"]
		self._PROTOCOL_COMBOBOX_CHOICES = ["HTTPS", "HTTP"]

		# create spacing for before and after each combo box choice to make combo boxes larger and center text with labels since the dropdown icon takes up space
		spacesForComboBox = ["      ", "    "]

		# add spacing before and after each combo box choice
		self._SEVERITY_COMBOBOX_CHOICES = [spacesForComboBox[0] + severity + spacesForComboBox[1] for severity in self._SEVERITY_COMBOBOX_CHOICES]
		self._CONFIDENCE_COMBOBOX_CHOICES = [spacesForComboBox[0] + confidence + spacesForComboBox[1] for confidence in self._CONFIDENCE_COMBOBOX_CHOICES]
		self._PROTOCOL_COMBOBOX_CHOICES = [spacesForComboBox[0] + protocol + spacesForComboBox[1] for protocol in self._PROTOCOL_COMBOBOX_CHOICES]

		# create a dictionaries for code reuse
		self._dictionaryOfTextAreas = dict()
		self._dictionaryOfTextPanes = dict()
		self._dictionaryOfScrollPanes = dict()
		self._dictionaryOfScrollPaneBorders = dict()
		self._dictionaryOfComboBoxes = dict()
		self._dictionaryOfPanels = dict()
		self._dictionaryOfSplitPanes = dict()
		self._dictionaryOfTables = dict()
		self._dictionaryOfTableRowSorters = dict()
		self._dictionaryOfButtons = dict()
		self._dictionaryOfLabels = dict()
		self._dictionaryOfLastSelectedRowsAndColumns = dict()

		# create main extension tab and issue selection tab for popup dialog
		self.createMainTabOrIssueSelectionTab(self._MAIN_TAB_NAME)
		self.createMainTabOrIssueSelectionTab(self._DIALOG_TAB_2_NAME)

		# create popup dialog to add a new issue
		self.createAddIssueDialog(self._DIALOG_TAB_1_NAME)

		# set the extension name
		callbacks.setExtensionName(self._EXTENSION_NAME)

		# register the context menu factory
		callbacks.registerContextMenuFactory(self)

		# customize UI components (recursive on child components) sets highlighted text in tables black instead of white. Will not center text in combo boxes
		callbacks.customizeUiComponent(self._dictionaryOfTables[self._MAIN_TAB_NAME])
		callbacks.customizeUiComponent(self._dictionaryOfTables[self._DIALOG_TAB_2_NAME])

		# add custom tab to Burp's UI
		callbacks.addSuiteTab(self)

		# print text to output window
		print(self._EXTENSION_NAME + " v" + self._EXTENSION_VERSION)
		print("Created by James Morris")
		print("https://github.com/JamesMorris-BurpSuite/")


		# end of BurpExtender
		return


	#
	# implement ITab - set tab caption
	#

	def getTabCaption(self):
		return self._EXTENSION_NAME


	#
	# implement ITab - set main component
	#

	def getUiComponent(self):
		return self._dictionaryOfSplitPanes[self._MAIN_TAB_NAME]


	#
	# create a menu item when right clicking on the site map, contents, proxy history, message viewers, ect.
	#

	def createMenuItems(self, invocation):

		# create a menu array
		menu = []

		# lambda has two parameters: x is menuActionOpenAddIssueDialog, and inv which is set to invocation
		menu.append(JMenuItem(self._EXTENSION_NAME[:-1], None, actionPerformed=lambda x, inv=invocation: self.menuActionOpenAddIssueDialog(inv)))

		# return menu if it exists
		return menu if menu else None


	#
	# create undo and redo on changes to the text areas
	#

	def createUndoRedo(self, longName):

		# try to check if the undo manager has been created
		try:
			# check if the undo manager has been created
			self._undoManager

		# undo manager has not been created
		except:
			# create an undo manager
			self._undoManager = UndoManager()

		# set undo keystroke to Ctrl+z
		undoKeystroke = KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_MASK)

		# set redo keystroke to Ctrl+Shift+z or Ctrl+y
		redoKeystroke1 = KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_MASK + InputEvent.SHIFT_MASK)
		redoKeystroke2 = KeyStroke.getKeyStroke(KeyEvent.VK_Y, InputEvent.CTRL_MASK)

		# create custom undoable edit listener
		undoRedoListener = CustomUndoableEditListener(self)

		# create undo action
		self._undoAction = CustomAbstractAction(self, "Undo")

		# create redo action
		self._redoAction = CustomAbstractAction(self, "Redo")

		# add undo redo listener to text area
		self._dictionaryOfTextAreas[longName].getDocument().addUndoableEditListener(undoRedoListener)

		# add undo action
		self._dictionaryOfTextAreas[longName].getInputMap().put(undoKeystroke, "undoKeystroke")
		self._dictionaryOfTextAreas[longName].getActionMap().put("undoKeystroke", self._undoAction)

		# add redo action
		self._dictionaryOfTextAreas[longName].getInputMap().put(redoKeystroke1, "redoKeystroke")
		self._dictionaryOfTextAreas[longName].getInputMap().put(redoKeystroke2, "redoKeystroke")
		self._dictionaryOfTextAreas[longName].getActionMap().put("redoKeystroke", self._redoAction)

		# return
		return


	#
	# create text areas, text panes, scroll panes, and panels
	#

	def createTextAndScrollPaneAndPanel(self, textType, editable, tabName, rowHeight, shortName):

		# create unique name for dictionary items
		longName = tabName + " " + shortName

		# check if the type is a text area
		if textType == "TextArea":

			# create text areas
			self._dictionaryOfTextAreas[longName] = CustomJTextArea("")

			# possible feature for the future, but it crowds everything and does not look as clean
			# create text editor for requests and responses that includes a search bar
			# if shortName == "Request" or shortName == "Response":
			#	self._dictionaryOfTextAreas[longName] = self._callbacks.createTextEditor().getComponent()

			# set row count to keep text areas from resizing when more or less text is displayed
			self._dictionaryOfTextAreas[longName].setRows(rowHeight)

			# set line wrap for text areas
			self._dictionaryOfTextAreas[longName].setLineWrap(True)

			# split new lines at words instead of characters
			self._dictionaryOfTextAreas[longName].setWrapStyleWord(True)

			# create scroll pane
			self._dictionaryOfScrollPanes[longName] = JScrollPane(self._dictionaryOfTextAreas[longName])

			# check if port
			if shortName == "Port":

				# set default port to 443 to match default protocol of https 
				self._dictionaryOfTextAreas[longName].setText("443")

			# check if issue name, port, host, or path
			if shortName == "Issue Name" or shortName == "Port" or shortName == "Host" or shortName == "Path":

				# disable newlines
				self._dictionaryOfTextAreas[longName].getDocument().putProperty("filterNewlines", True)

				# set custom filter to only allow valid ports
				self._dictionaryOfTextAreas[longName].getDocument().setDocumentFilter(CustomDocumentFilter(shortName))

			# check if text area is for port, host, or path
			if shortName == "Port" or shortName == "Host" or shortName == "Path":

				# add listener to text areas to build issue location as text is entered
				self._dictionaryOfTextAreas[longName].getDocument().addDocumentListener(CustomDocumentListener(self))

			# check if issue name, port, or host
			if shortName == "Issue Name" or shortName == "Port" or shortName == "Host":

				# store the default border in case border is turned red for missing information
				self._dictionaryOfScrollPaneBorders[longName] = self._dictionaryOfScrollPanes[longName].getBorder()

			# check if text area is not editable
			if editable == "editableN":

				# set to read only
				self._dictionaryOfTextAreas[longName].setEditable(False)

				# set disabled background color
				self._dictionaryOfTextAreas[longName].setBackground(self._DISABLED_BACKGROUND_COLOR)

			# text area is editable
			else:
				# allow undo and redo for changes to the text
				self.createUndoRedo(longName)

		# check if the type is a text pane
		elif textType == "TextPane":

			# create text pane
			self._dictionaryOfTextPanes[longName] = JTextPane()

			# set content type to html
			self._dictionaryOfTextPanes[longName].setContentType("text/html")

			# set text in text pane
			self._dictionaryOfTextPanes[longName].setText(self._HTML_FOR_TEXT_PANES[0] + "&nbsp" + self._HTML_FOR_TEXT_PANES[1])

			# remove default white border
			self._dictionaryOfTextPanes[longName].setBorder(BorderFactory.createEmptyBorder())

			# create scroll pane
			self._dictionaryOfScrollPanes[longName] = JScrollPane(self._dictionaryOfTextPanes[longName])

			# check if text pane is not editable
			if editable == "editableN":

				# set to read only
				self._dictionaryOfTextPanes[longName].setEditable(False)

				# set disabled background color
				self._dictionaryOfTextPanes[longName].setBackground(self._DISABLED_BACKGROUND_COLOR)

		# create panels
		self._dictionaryOfPanels[longName] = JPanel()

		# set border for panels
		self._dictionaryOfPanels[longName].setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.BLACK, 1, False), shortName, TitledBorder.CENTER, TitledBorder.TOP))

		# set layout for panels
		self._dictionaryOfPanels[longName].setLayout(BorderLayout())

		# add scroll panes to panels
		self._dictionaryOfPanels[longName].add(self._dictionaryOfScrollPanes[longName])

		# return
		return


	#
	# create combo boxes and panels
	#

	def createComboBoxAndPanel(self, tabName, shortName):

		# create unique name for dictionary items
		longName = tabName + " " + shortName

		# create combo box
		self._dictionaryOfComboBoxes[longName] = JComboBox()

		# check if combo box is for severity
		if shortName == "Severity":

			# loop through the choices
			for choice in self._SEVERITY_COMBOBOX_CHOICES:

				# add the choice
				self._dictionaryOfComboBoxes[longName].addItem(choice)

		# check if combo box is for confidence
		elif shortName == "Confidence":

			# loop through the choices
			for choice in self._CONFIDENCE_COMBOBOX_CHOICES:

				# add the choice
				self._dictionaryOfComboBoxes[longName].addItem(choice)

		# check if combo box is for protocol
		elif shortName == "Protocol":

			# loop through the choices
			for choice in self._PROTOCOL_COMBOBOX_CHOICES:

				# add the choice
				self._dictionaryOfComboBoxes[longName].addItem(choice)

			# add listener to combo box to build issue location as text is entered
			self._dictionaryOfComboBoxes[longName].addActionListener(CustomActionListener(self))

		# center combo box choices
		self._dictionaryOfComboBoxes[longName].getRenderer().setHorizontalAlignment(SwingConstants.CENTER)
		self._dictionaryOfComboBoxes[longName].getRenderer().setVerticalAlignment(SwingConstants.CENTER)

		# create panels
		self._dictionaryOfPanels[longName] = JPanel()

		# set border for panels
		self._dictionaryOfPanels[longName].setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.BLACK, 1, False), shortName, TitledBorder.CENTER, TitledBorder.TOP))

		# set layout for panels
		self._dictionaryOfPanels[longName].setLayout(BorderLayout())

		# add combo box to panels
		self._dictionaryOfPanels[longName].add(self._dictionaryOfComboBoxes[longName])

		# return
		return


	#
	# create buttons and button panels for the main tab
	#

	def createMainTabButtonAndButtonPanel(self, tabName, buttonName, halfWayPoint):

		# create button
		self._dictionaryOfButtons[buttonName] = JButton(buttonName, actionPerformed=lambda x, buttonClicked=buttonName: self.buttonActionButtonClickedFromMainTab(buttonClicked))

		#  create button panel
		self._dictionaryOfPanels[buttonName] = JPanel()

		# center button
		self._dictionaryOfPanels[buttonName].setLayout(GridBagLayout())

		# add button to button panel
		self._dictionaryOfPanels[buttonName].add(self._dictionaryOfButtons[buttonName])

		# add button panel to top main tab panel
		self._dictionaryOfPanels[tabName + " Buttons"].add(self._dictionaryOfPanels[buttonName])

		# check if half the button panels have been created
		if halfWayPoint:
			pass

		# return
		return


	#
	# create labels warning that the table has changed since the last export
	#
 
	def createWarningLabel(self, tabName, labelNumber):

		# create label setting text to blank since hiding label does not consume the space
		self._dictionaryOfLabels[tabName + labelNumber] = JLabel(" ")

		# center label
		self._dictionaryOfLabels[tabName + labelNumber].setHorizontalAlignment(JLabel.CENTER)
		self._dictionaryOfLabels[tabName + labelNumber].setVerticalAlignment(JLabel.CENTER)

		# set font color to red
		self._dictionaryOfLabels[tabName + labelNumber].setForeground(Color.RED)

		# set font to bold
		labelFont = self._dictionaryOfLabels[tabName + labelNumber].getFont()
		self._dictionaryOfLabels[tabName + labelNumber].setFont(labelFont.deriveFont(labelFont.getStyle() | Font.BOLD))

		# return
		return


	#
	# create a shared table model for multiple tables to use
	#

	def createSharedTableModel(self):

		# create variable to allow or disallow the table row to be unselected
		self._allowTableRowToBeUnselected = True

		# set the last selected row and column for both tables
		self._dictionaryOfLastSelectedRowsAndColumns[self._MAIN_TAB_NAME + " Row"] = -1
		self._dictionaryOfLastSelectedRowsAndColumns[self._MAIN_TAB_NAME + " Column"] = -1
		self._dictionaryOfLastSelectedRowsAndColumns[self._DIALOG_TAB_2_NAME + " Row"] = -1
		self._dictionaryOfLastSelectedRowsAndColumns[self._DIALOG_TAB_2_NAME + " Column"] = -1

		# create headers for the tables
		headers = ["Issue Name", "Severity", "Issue Detail", "Issue Background", "Remediation Detail", "Remediation Background"]

		# create custom default table model
		self._tableModelShared = CustomDefaultTableModel(None, headers)

		# populate the table with initial issues
		PopulateSharedTableModel(self).populate()

		# return
		return


	#
	# add panels with constraints to other panels
	#

	def addPanelWithConstraints(self, gridx, gridy, gridwidth, weightx, weighty, panelMain, panelToAdd, constraints):

		# set constraints
		constraints.gridx = gridx
		constraints.gridy = gridy
		constraints.gridwidth = gridwidth
		constraints.weightx = weightx
		constraints.weighty = weighty

		# add panel with constraints to dialog panel
		panelMain.add(panelToAdd, constraints)

		# return
		return


	#
	# create the main extension tab and issue selection tab for the popup dialog
	#

	def createMainTabOrIssueSelectionTab(self, tabName):

		# create panels
		self._dictionaryOfPanels[tabName + " Buttons"] = JPanel()
		self._dictionaryOfPanels[tabName + " Top North"] = JPanel()
		self._dictionaryOfPanels[tabName + " Top"] = JPanel()
		self._dictionaryOfPanels[tabName + " Bottom"] = JPanel()

		# set layout for panels
		self._dictionaryOfPanels[tabName + " Top North"].setLayout(BorderLayout())
		self._dictionaryOfPanels[tabName + " Top"].setLayout(BorderLayout())
		self._dictionaryOfPanels[tabName + " Bottom"].setLayout(GridBagLayout())

		##### Top Section - Start #####

		# check if main tab
		if tabName == self._MAIN_TAB_NAME:

			# create a custom grid layout
			customGridLayout = GridLayout(2, 3)

			# set vertical gap to help with spacing
			customGridLayout.setVgap(10)

			# set layout for button panel
			self._dictionaryOfPanels[tabName + " Buttons"].setLayout(customGridLayout)

			# set variable for the largest button size
			largestButtonSize = None

			# get the count of items in the array of buttons
			arrayLength = len(self._MAIN_TAB_BUTTON_NAMES)

			# loop through all of the button names for the main tab
			for index, buttonName in enumerate(self._MAIN_TAB_BUTTON_NAMES):

				# set variable if it is half way through the array
				halfWayPoint = (index + 1) == (arrayLength / 2)

				# create button and button panel
				self.createMainTabButtonAndButtonPanel(tabName, buttonName, halfWayPoint)

				# get the button size
				buttonSize = self._dictionaryOfButtons[buttonName].getPreferredSize()

				# check if the largest button size is set
				if largestButtonSize == None:

					# set the largest button size
					largestButtonSize = buttonSize

				# check if the button width is larger than the largest button size width
				elif buttonSize.getWidth() > largestButtonSize.getWidth():

					# set largest button size to the button size
					largestButtonSize = buttonSize

			# loop through all of the button names for the main tab
			for buttonName in self._MAIN_TAB_BUTTON_NAMES:

				# set button to largest button size
				self._dictionaryOfButtons[buttonName].setPreferredSize(largestButtonSize)

		# check if issue selection tab
		elif tabName == self._DIALOG_TAB_2_NAME:

			# set layout for button panel
			self._dictionaryOfPanels[tabName + " Buttons"].setLayout(GridBagLayout())

			# create button
			self._buttonSelectIssue = JButton("Add Information From Highlighted Issue", actionPerformed=lambda x, tab=tabName: self.buttonActionOpenAddIssueDialog(tab))

			# add button to top panel
			self._dictionaryOfPanels[tabName + " Buttons"].add(self._buttonSelectIssue)

		##### Middle Section - Start #####

		# try to check if the table model has been created
		try:
			# check if the table model has been created
			self._tableModelShared

		# table model has not been created
		except:
			# create a shared table model for the issue selection tab and main tab
			self.createSharedTableModel()

		# create custom JTable
		self._dictionaryOfTables[tabName] = CustomJTable(self, self._tableModelShared, tabName)

		# set preferred column widths for table
		self._dictionaryOfTables[tabName].getColumnModel().getColumn(0).setPreferredWidth(260)
		self._dictionaryOfTables[tabName].getColumnModel().getColumn(1).setPreferredWidth(50)
		self._dictionaryOfTables[tabName].getColumnModel().getColumn(2).setPreferredWidth(210)
		self._dictionaryOfTables[tabName].getColumnModel().getColumn(3).setPreferredWidth(210)
		self._dictionaryOfTables[tabName].getColumnModel().getColumn(4).setPreferredWidth(110)
		self._dictionaryOfTables[tabName].getColumnModel().getColumn(5).setPreferredWidth(210)

		# create custom table row sorter that can unsort
		self._dictionaryOfTableRowSorters[tabName] = CustomTableRowSorter(self._dictionaryOfTables[tabName].getModel())

		# set row sorter
		self._dictionaryOfTables[tabName].setRowSorter(self._dictionaryOfTableRowSorters[tabName])

		# only allow single rows to be selected
		self._dictionaryOfTables[tabName].setSelectionMode(ListSelectionModel.SINGLE_SELECTION)

		# create a custom mouse listener to detect if the mouse is clicked and dragging on the table to prevent the same row from being selected and unselected
		self._dictionaryOfTables[tabName].addMouseListener(CustomMouseListener(self))

		# set mouse state to detect if the mouse is clicked and dragging on the table to prevent the same row from being selected and unselected
		self._mouseState = None

		# create scroll pane
		self._dictionaryOfScrollPanes[tabName] = JScrollPane(self._dictionaryOfTables[tabName])

		##### Bottom Section - Start #####

		# create text areas, scroll panes, and panels
		self.createTextAndScrollPaneAndPanel("TextPane", "editableN", tabName, 0, "Issue Name")
		self.createTextAndScrollPaneAndPanel("TextPane", "editableN", tabName, 0, "Severity")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableN", tabName, 6, "Issue Detail")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableN", tabName, 6, "Issue Background")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableN", tabName, 6, "Remediation Detail")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableN", tabName, 6, "Remediation Background")

		# create grid bag constraints for main extension tab, popup dialog, and issue selection tab
		self._gridBagConstraints = GridBagConstraints()

		# fill vertically and horizontally
		self._gridBagConstraints.fill = GridBagConstraints.BOTH

		# set spacing
		self._gridBagConstraints.insets = Insets(0, 0, 0, 0)

		# first row
		self.addPanelWithConstraints(0, 1, 1, 1, 0, self._dictionaryOfPanels[tabName + " Bottom"], self._dictionaryOfPanels[tabName + " Issue Name"], self._gridBagConstraints)
		self.addPanelWithConstraints(1, 1, 1, 1, 0, self._dictionaryOfPanels[tabName + " Bottom"], self._dictionaryOfPanels[tabName + " Severity"], self._gridBagConstraints)

		# second row
		self.addPanelWithConstraints(0, 3, 1, 1, 0.5, self._dictionaryOfPanels[tabName + " Bottom"], self._dictionaryOfPanels[tabName + " Issue Detail"], self._gridBagConstraints)
		self.addPanelWithConstraints(1, 3, 1, 1, 0.5, self._dictionaryOfPanels[tabName + " Bottom"], self._dictionaryOfPanels[tabName + " Issue Background"], self._gridBagConstraints)

		# third row
		self.addPanelWithConstraints(0, 5, 1, 1, 0.5, self._dictionaryOfPanels[tabName + " Bottom"], self._dictionaryOfPanels[tabName + " Remediation Detail"], self._gridBagConstraints)
		self.addPanelWithConstraints(1, 5, 1, 1, 0.5, self._dictionaryOfPanels[tabName + " Bottom"], self._dictionaryOfPanels[tabName + " Remediation Background"], self._gridBagConstraints)

		# add space before each row of panels
		self.addPanelWithConstraints(0, 0, 2, 0, 0, self._dictionaryOfPanels[tabName + " Bottom"], JPanel(), self._gridBagConstraints)
		self.addPanelWithConstraints(0, 2, 2, 0, 0, self._dictionaryOfPanels[tabName + " Bottom"], JPanel(), self._gridBagConstraints)
		self.addPanelWithConstraints(0, 4, 2, 0, 0, self._dictionaryOfPanels[tabName + " Bottom"], JPanel(), self._gridBagConstraints)

		# create split pane
		self._dictionaryOfSplitPanes[tabName] = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._dictionaryOfSplitPanes[tabName].setResizeWeight(0.3)
		self._dictionaryOfSplitPanes[tabName].setDividerLocation(0.3)

		# create warning labels
		self.createWarningLabel(tabName, " 1")
		self.createWarningLabel(tabName, " 2")

		# set top north panel
		self._dictionaryOfPanels[tabName + " Top North"].add(self._dictionaryOfLabels[tabName + " 1"], BorderLayout.NORTH)
		self._dictionaryOfPanels[tabName + " Top North"].add(self._dictionaryOfPanels[tabName + " Buttons"], BorderLayout.CENTER)
		self._dictionaryOfPanels[tabName + " Top North"].add(self._dictionaryOfLabels[tabName + " 2"], BorderLayout.SOUTH)

		# set top panel
		self._dictionaryOfPanels[tabName + " Top"].add(self._dictionaryOfPanels[tabName + " Top North"], BorderLayout.NORTH)
		self._dictionaryOfPanels[tabName + " Top"].add(self._dictionaryOfScrollPanes[tabName], BorderLayout.CENTER)

		# set top and bottom of split pane
		self._dictionaryOfSplitPanes[tabName].setLeftComponent(self._dictionaryOfPanels[tabName + " Top"])
		self._dictionaryOfSplitPanes[tabName].setRightComponent(self._dictionaryOfPanels[tabName + " Bottom"])

		# check if tabName is the issue selection tab
		if tabName == self._DIALOG_TAB_2_NAME:

			# set flag to determine if the issue selection tab becomes visible for the first time to reset split pane location. Since it is not visible when created, it will not set correctly
			self._issueSelectionTabFirstTimeVisible = True

		# return
		return


	#
	# create the popup dialog to add a new issue from
	#

	def createAddIssueDialog(self, tabName):

		# create dialog box to add issues manually
		self._dialogAddIssue = JDialog()

		# hide dialog box
		self._dialogAddIssue.setVisible(False)

		# create panel for dialog box
		self._panelDialogAddIssueMain = JPanel()
		self._panelDialogAddIssueMain.setLayout(BorderLayout())

		# create top panel for first row of five columns
		self._panelDialogAddIssueTop = JPanel()
		self._panelDialogAddIssueTop.setLayout(GridBagLayout())

		# create bottom panel for all other rows of two columns
		self._panelDialogAddIssueBottom = JPanel()
		self._panelDialogAddIssueBottom.setLayout(GridBagLayout())

		# create text areas, scroll panes, and panels for main tab
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 1, "Issue Name")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 1, "Port")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 1, "Host")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 1, "Path")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableN", tabName, 1, "Issue Location")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 4, "Issue Detail")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 4, "Issue Background")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 4, "Remediation Detail")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 4, "Remediation Background")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 6, "Request")
		self.createTextAndScrollPaneAndPanel("TextArea", "editableY", tabName, 6, "Response")

		# create combo boxes and panels for main tab
		self.createComboBoxAndPanel(tabName, "Severity")
		self.createComboBoxAndPanel(tabName, "Confidence")
		self.createComboBoxAndPanel(tabName, "Protocol")


		# fill vertically and horizontally
		self._gridBagConstraints.fill = GridBagConstraints.BOTH

		# set spacing
		self._gridBagConstraints.insets = Insets(0, 0, 0, 0)

		# first row
		self.addPanelWithConstraints(0, 1, 1, 0.2, 0.02, self._panelDialogAddIssueTop, self._dictionaryOfPanels[tabName + " Issue Name"], self._gridBagConstraints)
		self.addPanelWithConstraints(1, 1, 1, 0.0, 0.02, self._panelDialogAddIssueTop, self._dictionaryOfPanels[tabName + " Severity"], self._gridBagConstraints)
		self.addPanelWithConstraints(2, 1, 1, 0.0, 0.02, self._panelDialogAddIssueTop, self._dictionaryOfPanels[tabName + " Confidence"], self._gridBagConstraints)
		self.addPanelWithConstraints(3, 1, 1, 0.0, 0.02, self._panelDialogAddIssueTop, self._dictionaryOfPanels[tabName + " Protocol"], self._gridBagConstraints)
		self.addPanelWithConstraints(4, 1, 1, 0.2, 0.02, self._panelDialogAddIssueTop, self._dictionaryOfPanels[tabName + " Port"], self._gridBagConstraints)

		# second row
		self.addPanelWithConstraints(0, 1, 1, 0.5, 0.05, self._panelDialogAddIssueBottom, self._dictionaryOfPanels[tabName + " Host"], self._gridBagConstraints)
		self.addPanelWithConstraints(1, 1, 1, 0.5, 0.05, self._panelDialogAddIssueBottom, self._dictionaryOfPanels[tabName + " Path"], self._gridBagConstraints)

		# third row
		self.addPanelWithConstraints(0, 3, 2, 1, 0.05, self._panelDialogAddIssueBottom, self._dictionaryOfPanels[tabName + " Issue Location"], self._gridBagConstraints)


		# fourth row
		self.addPanelWithConstraints(0, 5, 1, 1, 0.75, self._panelDialogAddIssueBottom, self._dictionaryOfPanels[tabName + " Issue Detail"], self._gridBagConstraints)
		self.addPanelWithConstraints(1, 5, 1, 1, 0.75, self._panelDialogAddIssueBottom, self._dictionaryOfPanels[tabName + " Issue Background"], self._gridBagConstraints)

		# fifth row
		self.addPanelWithConstraints(0, 7, 1, 1, 0.75, self._panelDialogAddIssueBottom, self._dictionaryOfPanels[tabName + " Remediation Detail"], self._gridBagConstraints)
		self.addPanelWithConstraints(1, 7, 1, 1, 0.75, self._panelDialogAddIssueBottom, self._dictionaryOfPanels[tabName + " Remediation Background"], self._gridBagConstraints)

		# sixth row
		self.addPanelWithConstraints(0, 9, 1, 0.5, 1, self._panelDialogAddIssueBottom, self._dictionaryOfPanels[tabName + " Request"], self._gridBagConstraints)
		self.addPanelWithConstraints(1, 9, 1, 0.5, 1, self._panelDialogAddIssueBottom, self._dictionaryOfPanels[tabName + " Response"], self._gridBagConstraints)

		# add space before each row of panels
		self.addPanelWithConstraints(0, 0, 5, 0, 0, self._panelDialogAddIssueTop, JPanel(), self._gridBagConstraints)
		self.addPanelWithConstraints(0, 0, 2, 0, 0, self._panelDialogAddIssueBottom, JPanel(), self._gridBagConstraints)
		self.addPanelWithConstraints(0, 2, 2, 0, 0, self._panelDialogAddIssueBottom, JPanel(), self._gridBagConstraints)
		self.addPanelWithConstraints(0, 4, 2, 0, 0, self._panelDialogAddIssueBottom, JPanel(), self._gridBagConstraints)
		self.addPanelWithConstraints(0, 6, 2, 0, 0, self._panelDialogAddIssueBottom, JPanel(), self._gridBagConstraints)
		self.addPanelWithConstraints(0, 8, 2, 0, 0, self._panelDialogAddIssueBottom, JPanel(), self._gridBagConstraints)

		# do not stretch button
		self._gridBagConstraints.fill = GridBagConstraints.NONE

		# create button
		self._buttonDialogAddIssue = JButton("    " + self._EXTENSION_NAME[:-1] + "    ", actionPerformed=self.buttonActionAddIssue)

		# add seventh row
		self.addPanelWithConstraints(0, 10, 2, 1, 0, self._panelDialogAddIssueBottom, self._buttonDialogAddIssue, self._gridBagConstraints)

		# add top and bottom panels to main panel
		self._panelDialogAddIssueMain.add(self._panelDialogAddIssueTop, BorderLayout.NORTH)
		self._panelDialogAddIssueMain.add(self._panelDialogAddIssueBottom, BorderLayout.CENTER)

		# create tabs for dialog box
		self._tabbedPaneDialog = JTabbedPane()
		self._tabbedPaneDialog.addTab(tabName, self._panelDialogAddIssueMain)
		self._tabbedPaneDialog.addTab(self._DIALOG_TAB_2_NAME, self._dictionaryOfSplitPanes[self._DIALOG_TAB_2_NAME])

		# add tabbed pane to dialog
		self._dialogAddIssue.add(self._tabbedPaneDialog)

		# set dialog size
		self._dialogAddIssue.setBounds(0, 0, 1200, 740)

		# set dialog title
		self._dialogAddIssue.setTitle(self._EXTENSION_NAME)

		# return
		return


	#
	# open the issue dialog from the menu choice
	#

	def menuActionOpenAddIssueDialog(self, invocation):

		# clear the popup dialog
		self.clearAddIssueDialog()

		# make the add issue dialog visible
		self.makeAddIssueDialogVisible()

		# set selected text area to issue name
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Name"].requestFocusInWindow()

		# set port to default value
		setPortToDefaultValue = False

		# check that the IHttpRequestResponse messages is not none and one exists in the array
		if invocation.getSelectedMessages() != None and len(invocation.getSelectedMessages()) > 0:

			# set the message
			invocationMessagesOrIssues = invocation.getSelectedMessages()

			# get message
			invocationMessagesOrIssue = invocationMessagesOrIssues[0]

		# check that the IScanIssue issues is not none and one exists in the array
		elif invocation.getSelectedIssues() != None and len(invocation.getSelectedIssues()) > 0:

			# set the issue
			invocationMessagesOrIssues = invocation.getSelectedIssues()

			# get issue
			invocationMessagesOrIssue = invocationMessagesOrIssues[0]

		# no message or issue
		else:
			# set to none
			invocationMessagesOrIssue = None

			# set port to default value instead of blank
			setPortToDefaultValue = True

		# try to get the http service
		try:
			# set http service
			httpService = invocationMessagesOrIssue.getHttpService()
		except:
			# set to blank
			httpService = ""

		# try to get the protocol
		try:
			# set protocol
			protocol = httpService.getProtocol()
		except:
			# set to blank
			protocol = ""

		# try to get the host
		try:
			# set host
			host = httpService.getHost()
		except:
			# set to blank
			host = ""

		# try to get the port
		try:
			# set port
			port = str(httpService.getPort())
		except:
			# check if the port should be set to the default value
			if setPortToDefaultValue:

				# set to blank
				port = "443"

			else:
				# set to blank
				port = ""

		# try to get the url
		try:
			# set url
			url = invocationMessagesOrIssue.getUrl()
		except:
			# set to blank
			url = ""

		# try to get the path
		try:
			# set path
			path = url.getPath()
		except:
			# set to blank
			path = ""

		# try to get the request
		try:
			# set request
			request = invocationMessagesOrIssue.getRequest().tostring()
		except:
			# set to blank
			request = ""

		# try to get the response
		try:
			# set response
			response = invocationMessagesOrIssue.getResponse().tostring()
		except:
			# set to blank
			response = ""

		# loop through each protocol choice for the combo box
		for protocolChoice in self._PROTOCOL_COMBOBOX_CHOICES:

			# check if the protocol choice matches the protocol
			if protocolChoice.strip().lower() == protocol:

				# set the protocol combo box to the protocol
				self._dictionaryOfComboBoxes[self._DIALOG_TAB_1_NAME + " Protocol"].setSelectedItem(protocolChoice)

				# do not continue through the choices
				break

		# set text fields
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Port"].setText(port)
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Host"].setText(host)
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Path"].setText(path)
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Request"].setText(request)
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Response"].setText(response)

		# return
		return


	#
	# open the issue dialog from the main tab button or the issue selection button
	#

	def buttonActionOpenAddIssueDialog(self, tabName):

		# get the selected row
		selectedRow = self._dictionaryOfTables[tabName].getSelectedRow()

		# check if a row was not selected and the dialog is visible
		if selectedRow == -1 and self._dialogAddIssue.isVisible():

			# check if the click was from the main tab
			if tabName == self._MAIN_TAB_NAME:

				# make the add issue dialog visible which brings it to the front
				self.makeAddIssueDialogVisible()

				# set selected text area to host since an issue name was filled in
				self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Name"].requestFocusInWindow()

			# do not continue
			return

		# check if the dialog is visible and a row was selected
		elif self._dialogAddIssue.isVisible():

			# make the add issue dialog visible which brings it to the front
			self.makeAddIssueDialogVisible()

			# set selected text area to host since an issue name was filled in
			self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Host"].requestFocusInWindow()

		# dialog is not visible
		else:
			# clear the popup dialog
			self.clearAddIssueDialog()

			# make the add issue dialog visible
			self.makeAddIssueDialogVisible()

			# check if a row was not selected
			if selectedRow == -1:

				# set selected text area to issue name since an issue was not selected
				self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Name"].requestFocusInWindow()

				# do not continue
				return

			# a row was selected
			else:
				# set selected text area to host since an issue name will be filled in
				self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Host"].requestFocusInWindow()

		# get the text from the html text pane
		textFromHtmlTextPaneIssueDetail = self._dictionaryOfTextPanes[tabName + " Issue Name"].getDocument().getText(0, self._dictionaryOfTextPanes[tabName + " Issue Name"].getDocument().getLength())

		# set add issue text to selected issue text
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Name"].setText(textFromHtmlTextPaneIssueDetail.strip())

		# set add issue text to selected issue text
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Detail"].setText(self._dictionaryOfTextAreas[tabName + " Issue Detail"].getText())
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Background"].setText(self._dictionaryOfTextAreas[tabName + " Issue Background"].getText())
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Remediation Detail"].setText(self._dictionaryOfTextAreas[tabName + " Remediation Detail"].getText())
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Remediation Background"].setText(self._dictionaryOfTextAreas[tabName + " Remediation Background"].getText())

		# scroll to top of text areas
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Name"].setCaretPosition(0)
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Detail"].setCaretPosition(0)
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Background"].setCaretPosition(0)
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Remediation Detail"].setCaretPosition(0)
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Remediation Background"].setCaretPosition(0)

		# get the text from the html text pane
		textFromHtmlTextPaneSeverity = self._dictionaryOfTextPanes[tabName + " Severity"].getDocument().getText(0, self._dictionaryOfTextPanes[tabName + " Severity"].getDocument().getLength())

		# loop through each severity choice
		for severityChoice in self._SEVERITY_COMBOBOX_CHOICES:

			# check if the selected severity is within the severity choice
			if severityChoice.strip() == textFromHtmlTextPaneSeverity.strip():

				# set the severity combo box to the selected row's severity
				self._dictionaryOfComboBoxes[self._DIALOG_TAB_1_NAME + " Severity"].setSelectedItem(severityChoice)

		# return
		return


	#
	# add the manually created issue or the imported issue to the issue table model
	#

	def addIssueToTableModel(self, issueName, severity, issueDetail, issueBackground, remediationDetail, remediationBackground):

		# create unique string from new issue
		newIssue = "0: " + issueName + "1: " + severity + "2: " + issueDetail + "3: " + issueBackground + "4: " + remediationDetail + "5: " + remediationBackground

		# set a variable to determine if the new issue is already in the table of issues
		issueNotInTable = True

		# get row and column counts 
		rowCount = self._tableModelShared.getRowCount()
		columnCount = self._tableModelShared.getColumnCount()

		# loop through each row in the table model
		for row in range(rowCount):

			# create unique string from issue in current row
			rowIssue = ""

			# loop through each column in the row
			for column in range(columnCount):

				# add column to row issue
				rowIssue += str(column) + ": " + self._tableModelShared.getValueAt(row, column)

			# check if the row issue matches the new issue
			if rowIssue == newIssue:

				# new issue is in the issue table
				issueNotInTable = False

				# do not continue looping
				break

		# check if the new issue is not in the issue table
		if issueNotInTable:

			# add new issue to issue table
			self._tableModelShared.addRow([issueName, severity, issueDetail, issueBackground, remediationDetail, remediationBackground])

			# show warning labels that table has been modified since last export
			self._dictionaryOfLabels[self._MAIN_TAB_NAME + " 1"].setText(self._WARNING_MESSAGE_TABLE_UPDATED)
			self._dictionaryOfLabels[self._MAIN_TAB_NAME + " 2"].setText(self._WARNING_MESSAGE_TABLE_UPDATED)
			self._dictionaryOfLabels[self._DIALOG_TAB_2_NAME + " 1"].setText(self._WARNING_MESSAGE_TABLE_UPDATED)
			self._dictionaryOfLabels[self._DIALOG_TAB_2_NAME + " 2"].setText(self._WARNING_MESSAGE_TABLE_UPDATED)

			# get the currently selected rows
			selectedRowMainTab = self._dictionaryOfTables[self._MAIN_TAB_NAME].getSelectedRow()
			selectedRowIssueSelectionTab = self._dictionaryOfTables[self._DIALOG_TAB_2_NAME].getSelectedRow()

			# check if a row has been selected
			if selectedRowMainTab != -1:

				# update the last selected row in case importing causes last selected row to stay at one index but highlighted row goes down a row
				self._dictionaryOfLastSelectedRowsAndColumns[self._MAIN_TAB_NAME + " Row"] = self._dictionaryOfTables[self._MAIN_TAB_NAME].convertRowIndexToModel(selectedRowMainTab)

			# check if a row has been selected
			if selectedRowIssueSelectionTab != -1:

				# update the last selected row in case importing causes last selected row to stay at one index but highlighted row goes down a row
				self._dictionaryOfLastSelectedRowsAndColumns[self._DIALOG_TAB_2_NAME + " Row"] = self._dictionaryOfTables[self._DIALOG_TAB_2_NAME].convertRowIndexToModel(selectedRowIssueSelectionTab)

		# return
		return


	#
	# add the manually created issue to the scan issue list and the issue tables
	#

	def buttonActionAddIssue(self, event):

		# get text area values from the dialog
		issueName = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Name"].getText()
		severity = self._dictionaryOfComboBoxes[self._DIALOG_TAB_1_NAME + " Severity"].getSelectedItem().strip()
		confidence = self._dictionaryOfComboBoxes[self._DIALOG_TAB_1_NAME + " Confidence"].getSelectedItem().strip()
		protocol = self._dictionaryOfComboBoxes[self._DIALOG_TAB_1_NAME + " Protocol"].getSelectedItem().strip().lower()
		port = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Port"].getText()
		host = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Host"].getText()
		path = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Path"].getText()
		location = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Location"].getText()
		issueDetail = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Detail"].getText()
		issueBackground = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Background"].getText()
		remediationDetail = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Remediation Detail"].getText()
		remediationBackground = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Remediation Background"].getText()
		request = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Request"].getText()
		response = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Response"].getText()

		# check if there is a value in the port field
		if port != "":

			# convert port to integer
			port = int(port)

		# check if path does not starts with a slash
		if not path.startswith("/"):

			# add slash to start of path
			path = "/" + path

		# create a message to display
		dialogMessage = ""

		# check if issue name is blank
		if issueName == "":

			# add to the dialog message
			dialogMessage += "Issue Name is blank.\n"

			# set red border
			self._dictionaryOfScrollPanes[self._DIALOG_TAB_1_NAME + " Issue Name"].setBorder(BorderFactory.createLineBorder(Color.RED, 2))

		# issue name not blank
		else:
			# set original border in case border was red
			self._dictionaryOfScrollPanes[self._DIALOG_TAB_1_NAME + " Issue Name"].setBorder(self._dictionaryOfScrollPaneBorders[self._DIALOG_TAB_1_NAME + " Issue Name"])

		# check if port is blank
		if port == "":

			# add to the dialog message
			dialogMessage += "Port is blank.\n"
#BorderFactory.createLineBorder(Color.RED, 2)

			originalDialogPortBorder = self._dictionaryOfScrollPanes[self._DIALOG_TAB_1_NAME + " Port"].getBorder()

			# set red border
			self._dictionaryOfScrollPanes[self._DIALOG_TAB_1_NAME + " Port"].setBorder(BorderFactory.createLineBorder(Color.RED, 2))

		# port not blank
		else:
			# set original border in case border was red
			self._dictionaryOfScrollPanes[self._DIALOG_TAB_1_NAME + " Port"].setBorder(self._dictionaryOfScrollPaneBorders[self._DIALOG_TAB_1_NAME + " Port"])

		# check if host is blank
		if host == "":

			# add to the dialog message
			dialogMessage += "Host is blank.\n"

			# set red border
			self._dictionaryOfScrollPanes[self._DIALOG_TAB_1_NAME + " Host"].setBorder(BorderFactory.createLineBorder(Color.RED, 2))

		# host not blank
		else:
			# set original border in case border was red
			self._dictionaryOfScrollPanes[self._DIALOG_TAB_1_NAME + " Host"].setBorder(self._dictionaryOfScrollPaneBorders[self._DIALOG_TAB_1_NAME + " Host"])

		# check that there is a name, port, and host
		if issueName == "" or port == "" or host == "":

			# display message that there is a missing item
			dialogOption = JOptionPane.showMessageDialog(None, "Please fill in all of the required information.\n" + dialogMessage, "Missing Information", JOptionPane.INFORMATION_MESSAGE)

			# do not continue
			return

		# hide dialog box
		self._dialogAddIssue.setVisible(False)

		# add issue to the table model
		self.addIssueToTableModel(issueName, severity, issueDetail, issueBackground, remediationDetail, remediationBackground)

		# create html line breaks since the normal line breaks do not carry over
		issueDetail = issueDetail.replace("\n", "<br>")
		issueBackground = issueBackground.replace("\n", "<br>")
		remediationDetail = remediationDetail.replace("\n", "<br>")
		remediationBackground = remediationBackground.replace("\n", "<br>")

		# create http service
		httpService = CustomIHttpService(protocol, host, port)

		# set comment and highlight
		comment = None
		highlight = None

		# create array of http messages
		httpMessages = [CustomIHttpRequestResponse(comment, highlight, httpService, request, response)]

		# create url
		url = URL(protocol + "://" + host + ":" + unicode(port) + path)

		# create new issue
		issue = CustomScanIssue(httpService, url, httpMessages, issueName, issueDetail, confidence, severity, issueBackground, remediationBackground, remediationDetail)

		# add new issue
		self._callbacks.addScanIssue(issue)

		# clear the popup dialog
		self.clearAddIssueDialog()

		# return
		return


	#
	# delete an issue from the table
	#

	def buttonClickedDeleteIssue(self):

		# get the selected row
		selectedRow = self._dictionaryOfTables[self._MAIN_TAB_NAME].getSelectedRow()

		# check that a row is selected
		if selectedRow != -1:

			# get index of selected row accounting for sorting
			modelRowIndex = self._dictionaryOfTables[self._MAIN_TAB_NAME].getRowSorter().convertRowIndexToModel(selectedRow)

			# delete the selected row
			self._dictionaryOfTables[self._MAIN_TAB_NAME].getModel().removeRow(modelRowIndex)

			# clear both tabs
			self.clearMainTabOrIssueSelectionTab(self._MAIN_TAB_NAME)
			self.clearMainTabOrIssueSelectionTab(self._DIALOG_TAB_2_NAME)

			# clear the selected row in the issue selection tab
			self._dictionaryOfTables[self._DIALOG_TAB_2_NAME].getSelectionModel().clearSelection()

			# check if the last row remaining in the table was deleted
			if selectedRow == 0 and self._dictionaryOfTables[self._MAIN_TAB_NAME].getRowCount() == 0:

				# clear selection
				self._dictionaryOfTables[self._MAIN_TAB_NAME].getSelectionModel().clearSelection()

				# do not continue
				return

			# check if the row that was selected was the last row
			elif selectedRow == self._dictionaryOfTables[self._MAIN_TAB_NAME].getRowCount():

				# select the new last row since the original last row was deleted
				selectedRow = selectedRow - 1

			# there is a row with data on the same line of the row that was deleted
			else:
				# keep same row selected
				pass

			# do not unselect the row
			self._allowTableRowToBeUnselected = False

			# keep a row selected after the selected one was deleted
			self._dictionaryOfTables[self._MAIN_TAB_NAME].changeSelection(selectedRow, 0, False, False)

			# set back to False
			self._allowTableRowToBeUnselected = True

			# show warning labels that table has been modified since last export
			self._dictionaryOfLabels[self._MAIN_TAB_NAME + " 1"].setText(self._WARNING_MESSAGE_TABLE_UPDATED)
			self._dictionaryOfLabels[self._MAIN_TAB_NAME + " 2"].setText(self._WARNING_MESSAGE_TABLE_UPDATED)
			self._dictionaryOfLabels[self._DIALOG_TAB_2_NAME + " 1"].setText(self._WARNING_MESSAGE_TABLE_UPDATED)
			self._dictionaryOfLabels[self._DIALOG_TAB_2_NAME + " 2"].setText(self._WARNING_MESSAGE_TABLE_UPDATED)

		# return
		return


	#
	# create dialog box for import and export
	#

	def createDialogBoxForImportExport(self, dialogTitle, extensionFilter, buttonText):

		# create frame
		frameImportExportDialogBox = JFrame()

		# create file chooser
		fileChooserImportExportDialogBox = JFileChooser()

		# set dialog title
		fileChooserImportExportDialogBox.setDialogTitle(dialogTitle)

		# create extension filter
		filterImportExportDialogBox = FileNameExtensionFilter(extensionFilter[0], extensionFilter[1])

		# set extension filter
		fileChooserImportExportDialogBox.setFileFilter(filterImportExportDialogBox)

		# show dialog box and get value
		valueFileChooserImportExportDialogBox = fileChooserImportExportDialogBox.showDialog(frameImportExportDialogBox, buttonText)

		# check if a file was not selected
		if valueFileChooserImportExportDialogBox != JFileChooser.APPROVE_OPTION:
		
			# return no path/file selected
			return False, "No Path/File"

		# get absolute path of file
		fileChosenImportExportDialogBox = fileChooserImportExportDialogBox.getSelectedFile().getAbsolutePath()

		# split name and extension
		fileNameImportExportDialogBox, fileExtensionImportExportDialogBox = os.path.splitext(fileChosenImportExportDialogBox)

		# check if file does not have an extention
		if fileExtensionImportExportDialogBox == "":

			# add extension to file
			fileChosenImportExportDialogBox = fileChosenImportExportDialogBox + extensionFilter[2]

		# return dialog box value and path/file
		return True, fileChosenImportExportDialogBox


	#
	# export issues from the table to a CSV file
	#

	def buttonClickedExportCsv(self):

		# set dialog options
		dialogBoxTitle = "Export CSV File"
		dialogBoxExtensionFilter = ["CSV Files (*.csv)", ["csv"], ".csv"]
		dialogBoxButtonText = "Export"

		# get the selected file
		fileChosen, fileImportExport = self.createDialogBoxForImportExport(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

		# return if user exited dialog box
		if fileChosen == False:
			return

		# open the file
		with open(fileImportExport, "wb") as csvFile:

			# create csv writer
			csvWriter = csv.writer(csvFile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

			# get the table size
			tableSize = self._dictionaryOfTables[self._MAIN_TAB_NAME].getRowCount()

			# loop through the table
			for i in range(0, tableSize):

				# create export variables for each row
				issueName = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 0)
				severity = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 1)
				issueDetails = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 2)
				issueBackground = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 3)
				remediationDetails = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 4)
				remediationBackground = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 5)

				# create a row to add
				csvRow = [issueName, severity, issueDetails, issueBackground, remediationDetails, remediationBackground]

				# write row to file
				csvWriter.writerow(csvRow)

		# show warning labels that table has been modified since last export
		self._dictionaryOfLabels[self._MAIN_TAB_NAME + " 1"].setText(" ")
		self._dictionaryOfLabels[self._MAIN_TAB_NAME + " 2"].setText(" ")
		self._dictionaryOfLabels[self._DIALOG_TAB_2_NAME + " 1"].setText(" ")
		self._dictionaryOfLabels[self._DIALOG_TAB_2_NAME + " 2"].setText(" ")

		# return
		return


	#
	# import issues from a CSV file to the table
	#

	def buttonClickedImportCsv(self):

		# set dialog options
		dialogBoxTitle = "Import CSV File"
		dialogBoxExtensionFilter = ["CSV Files (*.csv)", ["csv"], ".csv"]
		dialogBoxButtonText = "Import"

		# get the selected file
		fileChosen, fileImportExport = self.createDialogBoxForImportExport(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

		# return if user exited dialog box
		if fileChosen == False:
			return

		# set the limit to the max size
		csv.field_size_limit(sys.maxsize)

		# open the file
		with open(fileImportExport, "r") as csvFile:

			# read the csv
			csvReader = csv.reader(csvFile, delimiter=',', quotechar='"')

			# loop through each row in the csv file
			for row in csvReader:

				# get data from each row
				issueName = row[0]
				severity = row[1]
				issueDetail = row[2]
				issueBackground = row[3]
				remediationDetail = row[4]
				remediationBackground = row[5]

				# add issue to the table model
				self.addIssueToTableModel(issueName, severity, issueDetail, issueBackground, remediationDetail, remediationBackground)

		# return
		return


	#
	# export issues from the table to a JSON file
	#

	def buttonClickedExportJson(self):

		# set dialog options
		dialogBoxTitle = "Export JSON File"
		dialogBoxExtensionFilter = ["JSON Files (*.json)", ["json"], ".json"]
		dialogBoxButtonText = "Export"

		# get the selected file
		fileChosen, fileImportExport = self.createDialogBoxForImportExport(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

		# return if user exited dialog box
		if fileChosen == False:
			return

		# open the file
		with open(fileImportExport, "w") as jsonFile:

			# create a json dictionary
			jsonDictionaryIssues = {}

			# create an array for the issues
			jsonDictionaryIssues["Issues"] = []

			# get the table size
			tableSize = self._dictionaryOfTables[self._MAIN_TAB_NAME].getRowCount()

			# loop through the table
			for i in range(0, tableSize):

				# create a temp json for each row
				tempJson = {}

				# create temp variables for each row
				tempJson["Issue Name"] = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 0)
				tempJson["Severity"] = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 1)
				tempJson["Issue Details"] = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 2)
				tempJson["Issue Background"] = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 3)
				tempJson["Remediation Details"] = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 4)
				tempJson["Remediation Background"] = self._dictionaryOfTables[self._MAIN_TAB_NAME].getValueAt(i, 5)

				# export issues to json
				jsonDictionaryIssues["Issues"].append(tempJson)

			# write json to file
			jsonFile.write(json.dumps(jsonDictionaryIssues, ensure_ascii=False, indent=4, sort_keys=False, separators=(",", ": ")))

		# show warning labels that table has been modified since last export
		self._dictionaryOfLabels[self._MAIN_TAB_NAME + " 1"].setText(" ")
		self._dictionaryOfLabels[self._MAIN_TAB_NAME + " 2"].setText(" ")
		self._dictionaryOfLabels[self._DIALOG_TAB_2_NAME + " 1"].setText(" ")
		self._dictionaryOfLabels[self._DIALOG_TAB_2_NAME + " 2"].setText(" ")

		# return
		return


	#
	# import issues from a JSON file to the table
	#

	def buttonClickedImportJson(self):

		# set dialog options
		dialogBoxTitle = "Import JSON File"
		dialogBoxExtensionFilter = ["JSON Files (*.json)", ["json"], ".json"]
		dialogBoxButtonText = "Import"

		# get the selected file
		fileChosen, fileImportExport = self.createDialogBoxForImportExport(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

		# return if user exited dialog box
		if fileChosen == False:
			return

		# open the file
		with open(fileImportExport, "r") as jsonFile:

			# load the json data
			jsonData = json.load(jsonFile)

			# check if there is no data to import
			if jsonData["Issues"] == None :

				# do not continue
				return

			# loop through the json file
			for tempJson in jsonData["Issues"]:

				# get values to create new row in table
				issueName = tempJson["Issue Name"]
				severity = tempJson["Severity"]
				issueDetail = tempJson["Issue Details"]
				issueBackground = tempJson["Issue Background"]
				remediationDetail = tempJson["Remediation Details"]
				remediationBackground = tempJson["Remediation Background"]

				# add issue to the table model
				self.addIssueToTableModel(issueName, severity, issueDetail, issueBackground, remediationDetail, remediationBackground)

		# return
		return


	#
	# handle all button clicks from the main tab
	#

	def buttonActionButtonClickedFromMainTab(self, buttonClicked):

		# check if the add issue button was clicked
		if buttonClicked == self._MAIN_TAB_BUTTON_NAMES[0]:

			# add issue from main tab
			self.buttonActionOpenAddIssueDialog(self._MAIN_TAB_NAME)

		# check if the delete issue button was clicked
		elif buttonClicked == self._MAIN_TAB_BUTTON_NAMES[3]:

			# delete the issue
			self.buttonClickedDeleteIssue()

		# check if the export csv issues button was clicked
		elif buttonClicked == self._MAIN_TAB_BUTTON_NAMES[1]:

			# export csv
			self.buttonClickedExportCsv()

		# check if the import csv issues button was clicked
		elif buttonClicked == self._MAIN_TAB_BUTTON_NAMES[2]:

			# import csv
			self.buttonClickedImportCsv()

		# check if the export json issues button was clicked
		elif buttonClicked == self._MAIN_TAB_BUTTON_NAMES[4]:

			# export json
			self.buttonClickedExportJson()

		# check if the import json issues button was clicked
		elif buttonClicked == self._MAIN_TAB_BUTTON_NAMES[5]:

			# import json
			self.buttonClickedImportJson()

		# return
		return


	#
	# clear the main tab or the issue selection tab
	#

	def clearMainTabOrIssueSelectionTab(self, tabName):

		# clear text panes
		self._dictionaryOfTextPanes[tabName + " Issue Name"].setText(self._HTML_FOR_TEXT_PANES[0] + "&nbsp" + self._HTML_FOR_TEXT_PANES[1])
		self._dictionaryOfTextPanes[tabName + " Severity"].setText(self._HTML_FOR_TEXT_PANES[0] + "&nbsp" + self._HTML_FOR_TEXT_PANES[1])

		# clear text areas
		self._dictionaryOfTextAreas[tabName + " Issue Detail"].setText("")
		self._dictionaryOfTextAreas[tabName + " Issue Background"].setText("")
		self._dictionaryOfTextAreas[tabName + " Remediation Detail"].setText("")
		self._dictionaryOfTextAreas[tabName + " Remediation Background"].setText("")

		# return
		return


	#
	# clear the popup dialog
	#

	def clearAddIssueDialog(self):

		# clear text areas
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Name"].setText("")
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Port"].setText("443")
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Host"].setText("")
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Path"].setText("")
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Detail"].setText("")
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Background"].setText("")
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Remediation Detail"].setText("")
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Remediation Background"].setText("")
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Request"].setText("")
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Response"].setText("")

		# set combo boxes to defaults
		self._dictionaryOfComboBoxes[self._DIALOG_TAB_1_NAME + " Severity"].setSelectedItem(self._SEVERITY_COMBOBOX_CHOICES[0])
		self._dictionaryOfComboBoxes[self._DIALOG_TAB_1_NAME + " Confidence"].setSelectedItem(self._CONFIDENCE_COMBOBOX_CHOICES[0])
		self._dictionaryOfComboBoxes[self._DIALOG_TAB_1_NAME + " Protocol"].setSelectedItem(self._PROTOCOL_COMBOBOX_CHOICES[0])

		# return
		return


	#
	# make the add issue dialog visible
	#

	def makeAddIssueDialogVisible(self):

		# change focus to the add issue tab
	 	self._tabbedPaneDialog.setSelectedIndex(0)

		# make the dialog box visible in case the click is coming from the main tab
		self._dialogAddIssue.setVisible(True)

		# check if this is the first time the issue selection tab became visible
		if self._issueSelectionTabFirstTimeVisible == True:

			# change to false to prevent the divider location from resetting
			self._issueSelectionTabFirstTimeVisible = False

			# set the divider location since it will not set when it is creating since it was not visible
			self._dictionaryOfSplitPanes[self._DIALOG_TAB_2_NAME].setDividerLocation(0.3)

		# return
		return


	#
	# update the text area for the issue location
	#

	def updateTextAreaIssueLocation(self):

		# get the protocol by stripping spacing, converting to lowercase, and adding "://"
		protocol = self._dictionaryOfComboBoxes[self._DIALOG_TAB_1_NAME + " Protocol"].getSelectedItem().strip().lower() + "://"

		# get the host, port, and path
		host = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Host"].getText()
		port = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Port"].getText()
		path = self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Path"].getText()

		# check if the host and path are blank
		if host == "" and path == "":

			# set the location to blank
			self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Location"].setText("")

			# do not continue
			return

		# check if the host ends with a slash and does not only contain slashes and does not start with the protocol
		if host.endswith("/") and host != "https:/" and host != "http:/" and host != "https://" and host != "http://" and host.strip("/") != "":

			# remove last character
			host = host[:-1]

		# check if host is blank
		if host == "":

			# set message that a host is required
			host = protocol + "HOST_REQUIRED"

		# check that the host starts with https://
		elif host.startswith("https://"):

			# add protocol and remove "https://"
			host = protocol + host[8:]

		# check that the host starts with http://
		elif host.startswith("http://"):

			# add protocol and remove "http://"
			host = protocol + host[7:]

		# host is not blank
		else:
			# add protocol
			host = protocol + host

		# check if the port is blank
		if port == "":

			# set message that port is required
			port = ":PORT_REQUIRED"

		# port is not blank
		else:
			# add colon
			port = ":" + port

		# check that the first character of the path is not a slash
		if not path.startswith("/"):

			# add a slash
			path = "/" + path

		# set the location
		self._dictionaryOfTextAreas[self._DIALOG_TAB_1_NAME + " Issue Location"].setText(host + port + path)

		# return
		return


#
# extend IHttpService to create a custom http service for a custom IHttpRequestResponse and a custom IScanIssue
#

class CustomIHttpService(IHttpService):

	# initialize variables
	def __init__(self, protocol, host, port):
		self._protocol = protocol
		self._host = host
		self._port = port

	# override getProtocol
	def getProtocol(self):
		return self._protocol

	# override getHost
	def getHost(self):
		return self._host

	# override getPort
	def getPort(self):
		return self._port


#
# extend IHttpRequestResponse to create a request and response for a custom issue
#

class CustomIHttpRequestResponse(IHttpRequestResponse):

	# initialize variables
	def __init__(self, comment, highlight, httpService, request, response):
		self._comment = comment
		self._highlight = highlight
		self._httpService = httpService
		self._request = request
		self._response = response

	# override getRequest
	def getRequest(self):
		return self._request

	# override setRequest
	def setRequest(self, message):
		self._request = message

	# override getResponse
	def getResponse(self):
		return self._response

	# override setResponse
	def setResponse(self, message):
		self._response = message

	# override getComment
	def getComment(self):
		return self._comment

	# override setComment
	def setComment(self, comment):
		self._comment = comment

	# override getHighlight
	def getHighlight(self):
		return self._highlight

	# override setHighlight
	def setHighlight(self, color):
		self._highlight = color

	# override getHttpService
	def getHttpService(self):
		return self._httpService

	# override setHttpService
	def setHttpService(self, httpService):
		self._httpService = httpService


#
# extend IScanIssue to create a new issue
#

class CustomScanIssue(IScanIssue):

	# initialize variables
	def __init__(self, httpService, url, httpMessages, issueName, issueDetail, confidence, severity, issueBackground, remediationBackground, remediationDetail):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._issueName = issueName
		self._issueDetail = issueDetail
		self._confidence = confidence
		self._severity = severity
		self._issueBackground = issueBackground
		self._remediationBackground = remediationBackground
		self._remediationDetail = remediationDetail

		# set issue type to Extension Generated Issue 0x08000000 == 134217728
		self._issueType = 134217728

	# override getUrl
	def getUrl(self):
		return self._url

	# override getIssueName
	def getIssueName(self):
		return self._issueName

	# override getIssueType
	def getIssueType(self):
		return self._issueType

	# override getSeverity
	def getSeverity(self):
		return self._severity

	# override getConfidence
	def getConfidence(self):
		return self._confidence

	# override getIssueBackground
	def getIssueBackground(self):
		return self._issueBackground

	# override getRemediationBackground
	def getRemediationBackground(self):
		return self._remediationBackground

	# override getIssueDetail
	def getIssueDetail(self):
		return self._issueDetail

	# override getRemediationDetail
	def getRemediationDetail(self):
		return self._remediationDetail

	# override getHttpMessages
	def getHttpMessages(self):
		return self._httpMessages

	# override getHttpService
	def getHttpService(self):
		return self._httpService


#
# extend JTextArea to allow tab key to transfer focus to next item
#

class CustomJTextArea(JTextArea):

	# override processComponentKeyEvent
	def processComponentKeyEvent(self, event):

		# check if key code matches tab key code and that the key is being typed to avoid multiple triggers
		if event.getKeyCode() == KeyEvent.VK_TAB and event.getID() == KeyEvent.KEY_PRESSED:

			# cosume the event
			event.consume()

			# transfer focus to next area
			self.transferFocus()

		# check if key code matched tab key code and that event ID is KEY_RELEASED or KEY_TYPED
		elif event.getKeyCode() == KeyEvent.VK_TAB:

			# consume the event
			event.consume()


#
# extend CustomUndoableEditListener to allow undo and redo actions in text areas
#

class CustomUndoableEditListener(UndoableEditListener):

	# initialize variables
	def __init__(self, extender):
		self.extender = extender

	# override UndoAction
	def undoableEditHappened(self, event):
		self.extender._undoManager.addEdit(event.getEdit())
		self.extender._undoAction.update()
		self.extender._redoAction.update()


#
# extend CustomAbstractAction to allow undo and redo actions in text areas
#

class CustomAbstractAction(AbstractAction):

	# initialize variables
	def __init__(self, extender, undoOrRedo):
		self.extender = extender
		self.undoOrRedo = undoOrRedo

	# override UndoAction
	def UndoAction(self):
		AbstractAction.UndoAction(self.undoOrRedo)
		self.setEnabled(False)

	# override RedoAction
	def RedoAction(self):
		AbstractAction.RedoAction(self.undoOrRedo)
		self.setEnabled(False)

	# override actionPerformed
	def actionPerformed(self, event):

		# check if redo
		if self.undoOrRedo == "Redo":

			# try to redo
			try:
				# redo
				self.extender._undoManager.redo()

			except:
				pass

		# check if undo
		elif self.undoOrRedo == "Undo":

			# try to undo
			try:
				# undo
				self.extender._undoManager.undo()

			except:
				pass

		# update the undo and redo action
		self.extender._undoAction.update()
		self.extender._redoAction.update()

	# override update
	def update(self):

		# check if redo
		if self.undoOrRedo == "Redo":

			# check if redo can be performed
			if (self.extender._undoManager.canRedo()):

				self.setEnabled(True)
				self.putValue(Action.NAME, self.extender._undoManager.getRedoPresentationName())

			else:
				self.setEnabled(False)
				self.putValue(Action.NAME, self.undoOrRedo)
		# check if undo
		elif self.undoOrRedo == "Undo":

			# check if undo can be performed
			if (self.extender._undoManager.canUndo()):

				self.setEnabled(True)
				self.putValue(Action.NAME, self.extender._undoManager.getUndoPresentationName())

			else:
				self.setEnabled(False)
				self.putValue(Action.NAME, self.undoOrRedo)


#
# extend DocumentFilter to filter input for the issue name, host, port, and path
#

class CustomDocumentFilter(DocumentFilter):

	# initialize variables
	def __init__(self, filterType):
		self.filterType = filterType

	# override insertString
	def insertString(self, filterBypass, offset, string, attributeSet):

		# create string builder
		documentFilterBypass = filterBypass.getDocument()
		stringBuilder = StringBuilder()
		stringBuilder.append(documentFilterBypass.getText(0, documentFilterBypass.getLength()))
		stringBuilder.insert(offset, string)

		# check if value is valid
		if self.validateString(stringBuilder.toString()):

			# add default insertString
			DocumentFilter.insertString(self, filterBypass, offset, string, attributeSet)

	# override replace
	def replace(self, filterBypass, offset, length, text, attributeSet):

		# create string builder
		documentFilterBypass = filterBypass.getDocument()
		stringBuilder = StringBuilder()
		stringBuilder.append(documentFilterBypass.getText(0, documentFilterBypass.getLength()))
		stringBuilder.replace(offset, offset + length, text)

		# check if value is valid
		if self.validateString(stringBuilder.toString()):

			# add default replace
			DocumentFilter.replace(self, filterBypass, offset, length, text, attributeSet)

	# override remove
	def remove(self, filterBypass, offset, length):

		# create string builder
		documentFilterBypass = filterBypass.getDocument()
		stringBuilder = StringBuilder()
		stringBuilder.append(documentFilterBypass.getText(0, documentFilterBypass.getLength()))
		stringBuilder.delete(offset, offset + length)

		# check if value is valid
		if self.validateString(stringBuilder.toString()):

			# add default remove
			DocumentFilter.remove(self, filterBypass, offset, length)

	# validate if the string is allowed
	def validateString(self, text):

		# check if issue name filter
		if self.filterType == "Issue Name":

			# check if the text starts with a space
			if text.startswith(" "):

				# text is not allowed
				return False

			# does not start with a space
			else:
				# text is allowed 
				return True

		# check if port filter
		elif self.filterType == "Port":

			# set if text is blank
			blank = (text == "")

			# check if text is not blank
			if not blank:

				# try to check if text is an integer
				try:
					# check if text is an integer
					Integer.parseInt(text)

				# text was not an integer
				except:
					# text is not allowed
					return False

				# set if port is valid
				validPort = (int(text) > -1 and int(text) < 65536)

				# set if port does not start with zero and has a length of greater than one
				notStartWithZeroAndLengthGreaterThanOne = (not text.startswith("0") and len(text) > 1)

				# set if port length is 1
				lengthIsOne = (len(text) == 1)

			# check if the text is blank or (a valid port and ((does not start with zero and is greater than one) or (length is one)))
			if (blank or (validPort and (notStartWithZeroAndLengthGreaterThanOne or lengthIsOne))):

				# text is allowed
				return True
			else:
				# text is not allowed
				return False

		# host or path filter
		elif self.filterType == "Host" or self.filterType == "Path":

			# check if there is a space or newline character
			if " " in text or "\n" in text:

				# do not allow
				return False

			# no space or newline character
			else:
				return True


#
# extend DocumentListener to update the issue location when text is inserted or removed from the host, port, or path
#

class CustomDocumentListener(DocumentListener):

	# initialize variables
	def __init__(self, extender):
		self.extender = extender

	# override changedUpdate for when the style of text changes
	def changedUpdate(self, event):
		pass

	# override changedUpdate for when text is inserted
	def insertUpdate(self, event):

		# update the issue location text area
		self.extender.updateTextAreaIssueLocation()

	# override changedUpdate for when text is removed
	def removeUpdate(self, event):

		# update the issue location text area
		self.extender.updateTextAreaIssueLocation()


#
# extend ActionListener to update the issue location when the protocol combo box is changed
#

class CustomActionListener(ActionListener):

	# initialize variables
	def __init__(self, extender):
		self.extender = extender

	# override actionPerformed
	def actionPerformed(self, event):

		# get the selected protocol
		protocol = self.extender._dictionaryOfComboBoxes[self.extender._DIALOG_TAB_1_NAME + " Protocol"].getSelectedItem().strip()

		# get the port
		port = self.extender._dictionaryOfTextAreas[self.extender._DIALOG_TAB_1_NAME + " Port"].getText()

		# check if selected protocol is https and the current port is not 443
		if protocol == "HTTPS" and port != "443":

			# set port to 443
			self.extender._dictionaryOfTextAreas[self.extender._DIALOG_TAB_1_NAME + " Port"].setText("443")

		# check if selected protocol is http and the current port is not 80
		elif protocol == "HTTP" and port != "80":

			# set port to 80
			self.extender._dictionaryOfTextAreas[self.extender._DIALOG_TAB_1_NAME + " Port"].setText("80")

		# update the issue location text area
		self.extender.updateTextAreaIssueLocation()


#
# extend JTable to handle cell selection for tables
#

class CustomJTable(JTable):

	# initialize variables
	def __init__(self, extender, tableModel, tabName):
		self.extender = extender
		self.tableModel = tableModel
		self.setModel(tableModel)
		self.tabName = tabName

	# override changeSelection
	def changeSelection(self, row, column, toggle, extend):

		# get index of selected row
		modelRowIndex = self.convertRowIndexToModel(row)

		# get the last selected row and column
		selectedRow = self.extender._dictionaryOfLastSelectedRowsAndColumns[self.tabName + " Row"]
		selectedColumn = self.extender._dictionaryOfLastSelectedRowsAndColumns[self.tabName + " Column"]

		# get the mouse state to not update if the mouse is pressed
		mouseState = self.extender._mouseState

		# check if the same cell was clicked again and that the row should be unselected
		if selectedRow == modelRowIndex and selectedColumn == column and self.extender._allowTableRowToBeUnselected == True and mouseState == "Released":

			# set toggle and extend variables
			toggle = True
			extend = False

			# deselect row
			JTable.changeSelection(self, row, column, toggle, extend)

			# clear tab
			self.extender.clearMainTabOrIssueSelectionTab(self.tabName)

			# unselect the row
			self.clearSelection()

			# remove border from cell when unselected
			selectionModel = self.getSelectionModel()
			selectionModel.setAnchorSelectionIndex(-1)
			selectionModel.setLeadSelectionIndex(-1)

			# remove border from cell when unselected
			columnModel = self.getColumnModel()
			columnModel.getSelectionModel().setAnchorSelectionIndex(-1)
			columnModel.getSelectionModel().setLeadSelectionIndex(-1)

			# clear the last selected row and column
			self.extender._dictionaryOfLastSelectedRowsAndColumns[self.tabName + " Row"] = -1
			self.extender._dictionaryOfLastSelectedRowsAndColumns[self.tabName + " Column"] = -1

			# do not continue
			return

		# different row selected or same row but different column
		else:
			pass

		# set the last selected row and column
		self.extender._dictionaryOfLastSelectedRowsAndColumns[self.tabName + " Row"] = self.convertRowIndexToModel(row)
		self.extender._dictionaryOfLastSelectedRowsAndColumns[self.tabName + " Column"] = column

		# add default changeSelection
		JTable.changeSelection(self, row, column, toggle, extend)

		# get values from selected row
		selectedIssueName = self.getValueAt(row, 0)
		selectedSeverity = self.getValueAt(row, 1)
		selectedIssueDetail = self.getValueAt(row, 2)
		selectedIssueBackground = self.getValueAt(row, 3)
		selectedRemediationDetail = self.getValueAt(row, 4)
		selectedRemediationBackground = self.getValueAt(row, 5)

		# update text panes
		self.extender._dictionaryOfTextPanes[self.tabName + " Issue Name"].setText(self.extender._HTML_FOR_TEXT_PANES[0] + selectedIssueName + self.extender._HTML_FOR_TEXT_PANES[1])
		self.extender._dictionaryOfTextPanes[self.tabName + " Severity"].setText(self.extender._HTML_FOR_TEXT_PANES[0] + selectedSeverity + self.extender._HTML_FOR_TEXT_PANES[1])

		# update text areas
		self.extender._dictionaryOfTextAreas[self.tabName + " Issue Detail"].setText(selectedIssueDetail)
		self.extender._dictionaryOfTextAreas[self.tabName + " Issue Background"].setText(selectedIssueBackground)
		self.extender._dictionaryOfTextAreas[self.tabName + " Remediation Detail"].setText(selectedRemediationDetail)
		self.extender._dictionaryOfTextAreas[self.tabName + " Remediation Background"].setText(selectedRemediationBackground)

		# scroll to top of text panes
		self.extender._dictionaryOfTextPanes[self.tabName + " Issue Name"].setCaretPosition(0)
		self.extender._dictionaryOfTextPanes[self.tabName + " Severity"].setCaretPosition(0)

		# scroll to top of text areas
		self.extender._dictionaryOfTextAreas[self.tabName + " Issue Detail"].setCaretPosition(0)
		self.extender._dictionaryOfTextAreas[self.tabName + " Issue Background"].setCaretPosition(0)
		self.extender._dictionaryOfTextAreas[self.tabName + " Remediation Detail"].setCaretPosition(0)
		self.extender._dictionaryOfTextAreas[self.tabName + " Remediation Background"].setCaretPosition(0)


#
# extend DefaultTableModel to make table cells uneditable
#

class CustomDefaultTableModel(DefaultTableModel):

	# override isCellEditable
	def isCellEditable(self, row, column):

		# make cell uneditable
		return False


#
# extend TableRowSorter to toggle sorting (ascending, descending, unsorted)
#

class CustomTableRowSorter(TableRowSorter):

	# override toggleSortOrder
	def toggleSortOrder(self, column):

		# check if valid column 
		if column >= 0:

			# get the sort keys
			keys = self.getSortKeys()

			# check if the sort keys are not empty
			if keys.isEmpty() == False:

				# get the sort key
				sortKey = keys.get(0)

				# check if the column clicked is sorted in descending order
				if sortKey.getColumn() == column and sortKey.getSortOrder() == SortOrder.DESCENDING:

					# clear sorting
					self.setSortKeys(None)

					# do not continue
					return

		# toggle default toggleSortOrder
		TableRowSorter.toggleSortOrder(self, column)


#
# extend MouseListener to detect mouse clicks on tables so row doesn't flash (select and unselect constantly) when dragging a clicked mouse
#

class CustomMouseListener(MouseListener):

	# initialize variables
	def __init__(self, extender):
		self.extender = extender

	# override mousePressed
	def mousePressed(self, event):

		# set mouse state
		self.extender._mouseState = "Pressed"

	# override mouseReleased
	def mouseReleased(self, event):

		# set mouse state
		self.extender._mouseState = "Released"

	# override mouseClicked
	def mouseClicked(self, event):
		pass

	# override mouseEntered
	def mouseEntered(self, event):
		pass

	# override mouseExited
	def mouseExited(self, event):
		pass


#
# populate the shared table model with some default issues to choose from
#

class PopulateSharedTableModel():

	# initialize variables
	def __init__(self, extender):
		self.extender = extender

	# populate the table model
	def populate(self):

		# create a new issue for the table model
		# tempIssueName = ""
		# tempSeverity = ""
		# tempIssueDetail = ""
		# tempIssueBackground = ""
		# tempRemediationDetail = ""
		# tempRemediationBackground = ""
		# self._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Cleartext Submission Of Password"
		tempSeverity = "High"
		tempIssueDetail = "A Cleartext Submission Of Password vulnerability was discovered."
		tempIssueBackground = "Some applications transmit passwords over unencrypted connections, making them vulnerable to interception. To exploit this vulnerability, an attacker must be suitably positioned to eavesdrop on the victim's network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.\n\nVulnerabilities that result in the disclosure of users' passwords can result in compromises that are extremely difficult to investigate due to obscured audit trails. Even if the application itself only handles non-sensitive information, exposing passwords puts users who have re-used their password elsewhere at risk."
		tempRemediationDetail = ""
		tempRemediationBackground = "Applications should use transport-level encryption (SSL or TLS) to protect all sensitive communications passing between the client and the server. Communications that should be protected include the login mechanism and related functionality, and any functions where sensitive data can be accessed or privileged actions can be performed. These areas should employ their own session handling mechanism, and the session tokens used should never be transmitted over unencrypted communications. If HTTP cookies are used for transmitting session tokens, then the secure flag should be set to prevent transmission over clear-text HTTP."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Cross-Site Scripting (XSS) - DOM-Based"
		tempSeverity = "High"
		tempIssueDetail = "A DOM-Based Cross-Site Scripting (XSS) vulnerability was discovered."
		tempIssueBackground = "DOM-based vulnerabilities arise when a client-side script reads data from a controllable part of the DOM (for example, the URL) and processes this data in an unsafe way.\n\nDOM-based cross-site scripting arises when a script writes controllable data into the HTML document in an unsafe way. An attacker may be able to use the vulnerability to construct a URL that, if visited by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.\n\nThe attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.\n\nUsers can be induced to visit the attacker's crafted URL in various ways, similar to the usual attack delivery vectors for reflected cross-site scripting vulnerabilities.\n\nBurp Suite automatically identifies this issue using static code analysis, which may lead to false positives that are not actually exploitable. The relevant code and execution paths should be reviewed to determine whether this vulnerability is indeed present, or whether mitigations are in place that would prevent exploitation."
		tempRemediationDetail = ""
		tempRemediationBackground = "The most effective way to avoid DOM-based cross-site scripting vulnerabilities is not to dynamically write data from any untrusted source into the HTML document. If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code to prevent malicious data from introducing script code into the document. In many cases, the relevant data can be validated on a whitelist basis, to allow only content that is known to be safe. In other cases, it will be necessary to sanitize or encode the data. This can be a complex task, and depending on the context that the data is to be inserted may need to involve a combination of JavaScript escaping, HTML encoding, and URL encoding, in the appropriate sequence."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Cross-Site Scripting (XSS) - Reflected"
		tempSeverity = "High"
		tempIssueDetail = "A Reflected Cross-Site Scripting (XSS) vulnerability was discovered."
		tempIssueBackground = "Reflected cross-site scripting vulnerabilities arise when data is copied from a request and echoed into the application's immediate response in an unsafe way. An attacker can use the vulnerability to construct a request that, if issued by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.\n\nThe attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.\n\nUsers can be induced to issue the attacker's crafted request in various ways. For example, the attacker can send a victim a link containing a malicious URL in an email or instant message. They can submit the link to popular web sites that allow content authoring, for example in blog comments. And they can create an innocuous looking web site that causes anyone viewing it to make arbitrary cross-domain requests to the vulnerable application (using either the GET or the POST method).\n\nThe security impact of cross-site scripting vulnerabilities is dependent upon the nature of the vulnerable application, the kinds of data and functionality that it contains, and the other applications that belong to the same domain and organization. If the application is used only to display non-sensitive public content, with no authentication or access control functionality, then a cross-site scripting flaw may be considered low risk. However, if the same application resides on a domain that can access cookies for other more security-critical applications, then the vulnerability could be used to attack those other applications, and so may be considered high risk. Similarly, if the organization that owns the application is a likely target for phishing attacks, then the vulnerability could be leveraged to lend credibility to such attacks, by injecting Trojan functionality into the vulnerable application and exploiting users' trust in the organization in order to capture credentials for other applications that it owns. In many kinds of application, such as those providing online banking functionality, cross-site scripting should always be considered high risk."
		tempRemediationDetail = ""
		tempRemediationBackground = "In most situations where user-controllable data is copied into application responses, cross-site scripting attacks can be prevented using two layers of defenses:\n\nInput should be validated as strictly as possible on arrival, given the kind of content that it is expected to contain. For example, personal names should consist of alphabetical and a small range of typographical characters, and be relatively short; a year of birth should consist of exactly four numerals; email addresses should match a well-defined regular expression. Input which fails the validation should be rejected, not sanitized.\n\nUser input should be HTML-encoded at any point where it is copied into application responses. All HTML metacharacters, including < > \" ' and =, should be replaced with the corresponding HTML entities (&lt; &gt; etc).\n\nIn cases where the application's functionality allows users to author content using a restricted subset of HTML tags and attributes (for example, blog comments which allow limited formatting and linking), it is necessary to parse the supplied HTML to validate that it does not use any dangerous syntax; this is a non-trivial task."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Cross-Site Scripting (XSS) - Stored"
		tempSeverity = "High"
		tempIssueDetail = "A Stored Cross-Site Scripting (XSS) vulnerability was discovered."
		tempIssueBackground = "Stored cross-site scripting vulnerabilities arise when user input is stored and later embedded into the application's responses in an unsafe way. An attacker can use the vulnerability to inject malicious JavaScript code into the application, which will execute within the browser of any user who views the relevant application content.\n\nThe attacker-supplied code can perform a wide variety of actions, such as stealing victims' session tokens or login credentials, performing arbitrary actions on their behalf, and logging their keystrokes.\n\nMethods for introducing malicious content include any function where request parameters or headers are processed and stored by the application, and any out-of-band channel whereby data can be introduced into the application's processing space (for example, email messages sent over SMTP that are ultimately rendered within a web mail application).\n\nStored cross-site scripting flaws are typically more serious than reflected vulnerabilities because they do not require a separate delivery mechanism in order to reach target users, and are not hindered by web browsers' XSS filters. Depending on the affected page, ordinary users may be exploited during normal use of the application. In some situations this can be used to create web application worms that spread exponentially and ultimately exploit all active users.\n\nNote that automated detection of stored cross-site scripting vulnerabilities cannot reliably determine whether attacks that are persisted within the application can be accessed by any other user, only by authenticated users, or only by the attacker themselves. You should review the functionality in which the vulnerability appears to determine whether the application's behavior can feasibly be used to compromise other application users."
		tempRemediationDetail = ""
		tempRemediationBackground = "In most situations where user-controllable data is copied into application responses, cross-site scripting attacks can be prevented using two layers of defenses:\n\nInput should be validated as strictly as possible on arrival, given the kind of content that it is expected to contain. For example, personal names should consist of alphabetical and a small range of typographical characters, and be relatively short; a year of birth should consist of exactly four numerals; email addresses should match a well-defined regular expression. Input which fails the validation should be rejected, not sanitized.\n\nUser input should be HTML-encoded at any point where it is copied into application responses. All HTML metacharacters, including < > \" ' and =, should be replaced with the corresponding HTML entities (&lt; &gt; etc).\n\nIn cases where the application's functionality allows users to author content using a restricted subset of HTML tags and attributes (for example, blog comments which allow limited formatting and linking), it is necessary to parse the supplied HTML to validate that it does not use any dangerous syntax; this is a non-trivial task."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Directory Traversal (File Path Traversal '../')"
		tempSeverity = "High"
		tempIssueDetail = "A Directory Traversal (File Path Traversal '../') vulnerability was discovered."
		tempIssueBackground = "File path traversal vulnerabilities arise when user-controllable data is used within a filesystem operation in an unsafe manner. Typically, a user-supplied filename is appended to a directory prefix in order to read or write the contents of a file. If vulnerable, an attacker can supply path traversal sequences (using dot-dot-slash characters) to break out of the intended directory and read or write files elsewhere on the filesystem.\n\nThis is typically a very serious vulnerability, enabling an attacker to access sensitive files containing configuration data, passwords, database records, log data, source code, and program scripts and binaries."
		tempRemediationDetail = ""
		tempRemediationBackground = "Ideally, application functionality should be designed in such a way that user-controllable data does not need to be passed to filesystem operations. This can normally be achieved by referencing known files via an index number rather than their name, and using application-generated filenames to save user-supplied file content.\n\nIf it is considered unavoidable to pass user-controllable data to a filesystem operation, three layers of defense can be employed to prevent path traversal attacks:\n\nUser-controllable data should be strictly validated before being passed to any filesystem operation. In particular, input containing dot-dot sequences should be blocked.\n\nAfter validating user input, the application can use a suitable filesystem API to verify that the file to be accessed is actually located within the base directory used by the application. In Java, this can be achieved by instantiating a java.io.File object using the user-supplied filename and then calling the getCanonicalPath method on this object. If the string returned by this method does not begin with the name of the start directory, then the user has somehow bypassed the application's input filters, and the request should be rejected. In ASP.NET, the same check can be performed by passing the user-supplied filename to the System.Io.Path.GetFullPath method and checking the returned string in the same way as described for Java.\n\nThe directory used to store files that are accessed using user-controllable data can be located on a separate logical volume to other sensitive application and operating system files, so that these cannot be reached via path traversal attacks. In Unix-based systems, this can be achieved using a chrooted filesystem; on Windows, this can be achieved by mounting the base directory as a new logical drive and using the associated drive letter to access its contents."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "File Path Manipulation"
		tempSeverity = "High"
		tempIssueDetail = "A File Path Manipulation vulnerability was discovered."
		tempIssueBackground = "File path manipulation vulnerabilities arise when user-controllable data is placed into a file or URL path that is used on the server to access local resources, which may be within or outside the web root. If vulnerable, an attacker can modify the file path to access different resources, which may contain sensitive information. Even where an attack is constrained within the web root, it is often possible to retrieve items that are normally protected from direct access, such as application configuration files, the source code for server-executable scripts, or files with extensions that the web server is not configured to serve directly."
		tempRemediationDetail = ""
		tempRemediationBackground = "Ideally, application functionality should be designed in such a way that user-controllable data does not need to be placed into file or URL paths in order to access local resources on the server. This can normally be achieved by referencing known files via an index number rather than their name.\n\nIf it is considered unavoidable to place user data into file or URL paths, the data should be strictly validated against a whitelist of accepted values. Note that when accessing resources within the web root, simply blocking input containing file path traversal sequences (such as dot-dot-slash) is not always sufficient to prevent retrieval of sensitive information, because some protected items may be accessible at the original path without using any traversal sequences."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "LDAP Injection"
		tempSeverity = "High"
		tempIssueDetail = "An LDAP Injection vulnerability was discovered."
		tempIssueBackground = "LDAP injection arises when user-controllable data is copied in an unsafe way into an LDAP query that is performed by the application. If an attacker can inject LDAP metacharacters into the query, then they can interfere with the query's logic. Depending on the function for which the query is used, the attacker may be able to retrieve sensitive data to which they are not authorized, or subvert the application's logic to perform some unauthorized action.\n\nNote that automated difference-based tests for LDAP injection flaws can often be unreliable and are prone to false positive results. Scanner results should be manually reviewed to confirm whether a vulnerability is actually present."
		tempRemediationDetail = ""
		tempRemediationBackground = "If possible, applications should avoid copying user-controllable data into LDAP queries. If this is unavoidable, then the data should be strictly validated to prevent LDAP injection attacks. In most situations, it will be appropriate to allow only short alphanumeric strings to be copied into queries, and any other input should be rejected. At a minimum, input containing any LDAP metacharacters should be rejected; characters that should be blocked include ( ) ; , * | & = and whitespace."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "OS Command Injection"
		tempSeverity = "High"
		tempIssueDetail = "An OS Command Injection vulnerability was discovered."
		tempIssueBackground = "Operating system command injection vulnerabilities arise when an application incorporates user-controllable data into a command that is processed by a shell command interpreter. If the user data is not strictly validated, an attacker can use shell metacharacters to modify the command that is executed, and inject arbitrary further commands that will be executed by the server.\n\nOS command injection vulnerabilities are usually very serious and may lead to compromise of the server hosting the application, or of the application's own data and functionality. It may also be possible to use the server as a platform for attacks against other systems. The exact potential for exploitation depends upon the security context in which the command is executed, and the privileges that this context has regarding sensitive resources on the server."
		tempRemediationDetail = ""
		tempRemediationBackground = "If possible, applications should avoid incorporating user-controllable data into operating system commands. In almost every situation, there are safer alternative methods of performing server-level tasks, which cannot be manipulated to perform additional commands than the one intended.\n\nIf it is considered unavoidable to incorporate user-supplied data into operating system commands, the following two layers of defense should be used to prevent attacks:\n\nThe user data should be strictly validated. Ideally, a whitelist of specific accepted values should be used. Otherwise, only short alphanumeric strings should be accepted. Input containing any other data, including any conceivable shell metacharacter or whitespace, should be rejected.\n\nThe application should use command APIs that launch a specific process via its name and command-line parameters, rather than passing a command string to a shell interpreter that supports command chaining and redirection. For example, the Java API Runtime.exec and the ASP.NET API Process.Start do not support shell metacharacters. This defense can mitigate the impact of an attack even in the event that an attacker circumvents the input validation defenses."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Out-Of-Band Resource Load (HTTP)"
		tempSeverity = "High"
		tempIssueDetail = "An Out-Of-Band Resource Load (HTTP) vulnerability was discovered."
		tempIssueBackground = "Out-of-band resource load arises when it is possible to induce an application to fetch content from an arbitrary external location, and incorporate that content into the application's own response(s). The ability to trigger arbitrary out-of-band resource load does not constitute a vulnerability in its own right, and in some cases might even be the intended behavior of the application. However, in many cases, it can indicate a vulnerability with serious consequences.\n\nThe ability to request and retrieve web content from other systems can allow the application server to be used as a two-way attack proxy. By submitting suitable payloads, an attacker can cause the application server to attack, or retrieve content from, other systems that it can interact with. This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself. Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers.\n\nAdditionally, the application's processing of web content that is retrieved from arbitrary URLs exposes some important and non-conventional attack surface. An attacker can deploy a web server that returns malicious content, and then induce the application to retrieve and process that content. This processing might give rise to the types of input-based vulnerabilities that are normally found when unexpected input is submitted directly in requests to the application. The out-of-band attack surface that the application exposes should be thoroughly tested for these types of vulnerabilities."
		tempRemediationDetail = ""
		tempRemediationBackground = "You should review the purpose and intended use of the relevant application functionality, and determine whether the ability to trigger arbitrary out-of-band resource load is intended behavior. If so, you should be aware of the types of attacks that can be performed via this behavior and take appropriate measures. These measures might include blocking network access from the application server to other internal systems, and hardening the application server itself to remove any services available on the local loopback adapter. You should also ensure that content retrieved from other systems is processed in a safe manner, with the usual precautions that are applicable when processing input from direct incoming web requests.\n\nIf the ability to trigger arbitrary out-of-band resource load is not intended behavior, then you should implement a whitelist of permitted URLs, and block requests to URLs that do not appear on this whitelist."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "SQL Injection (SQLi)"
		tempSeverity = "High"
		tempIssueDetail = "A SQL Injection (SQLi) vulnerability was discovered."
		tempIssueBackground = "SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.\n\nA wide range of damaging attacks can often be delivered via SQL injection, including reading or modifying critical application data, interfering with application logic, escalating privileges within the database and taking control of the database server."
		tempRemediationDetail = ""
		tempRemediationBackground = "The most effective way to prevent SQL injection attacks is to use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into SQL queries: first, the application specifies the structure of the query, leaving placeholders for each item of user input; second, the application specifies the contents of each placeholder. Because the structure of the query has already been defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure. You should review the documentation for your database and application platform to determine the appropriate APIs which you can use to perform parameterized queries. It is strongly recommended that you parameterize every variable data item that is incorporated into database queries, even if it is not obviously tainted, to prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application.\n\nYou should be aware that some commonly employed and recommended mitigations for SQL injection vulnerabilities are not always effective:\n\nOne common defense is to double up any single quotation marks appearing within user input before incorporating that input into a SQL query. This defense is designed to prevent malformed data from terminating the string into which it is inserted. However, if the data being incorporated into queries is numeric, then the defense may fail, because numeric data may not be encapsulated within quotes, in which case only a space is required to break out of the data context and interfere with the query. Further, in second-order SQL injection attacks, data that has been safely escaped when initially inserted into the database is subsequently read from the database and then passed back to it again. Quotation marks that have been doubled up initially will return to their original form when the data is reused, allowing the defense to be bypassed.\n\nAnother often cited defense is to use stored procedures for database access. While stored procedures can provide security benefits, they are not guaranteed to prevent SQL injection attacks. The same kinds of vulnerabilities that arise within standard dynamic SQL queries can arise if any SQL is dynamically constructed within stored procedures. Further, even if the procedure is sound, SQL injection can arise if the procedure is invoked in an unsafe manner using user-controllable data."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "User Enumeration"
		tempSeverity = "High"
		tempIssueDetail = "Valid usernames can be distinguished from invalid usernames."
		tempIssueBackground = "Valid usernames can be identified based on the response of the web application."
		tempRemediationDetail = ""
		tempRemediationBackground = "The server should response with a generic message for both valid and invalid usernames."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "XML External Entity Injection (XXE)"
		tempSeverity = "High"
		tempIssueDetail = "An XML External Entity Injection (XXE) vulnerability was discovered."
		tempIssueBackground = "XML external entity (XXE) injection vulnerabilities arise when applications process user-supplied XML documents without disabling references to external resources. XML parsers typically support external references by default, even though they are rarely required by applications during normal usage.\n\nExternal entities can reference files on the parser's filesystem; exploiting this feature may allow retrieval of arbitrary files, or denial of service by causing the server to read from a file such as /dev/random.\n\nExternal entities can often also reference network resources via the HTTP protocol handler. The ability to send requests to other systems can allow the vulnerable server to be used as an attack proxy. By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself. Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers."
		tempRemediationDetail = ""
		tempRemediationBackground = "Parsers that are used to process XML from untrusted sources should be configured to disable processing of all external resources. This is usually possible, and will prevent a number of related attacks. You should consult the documentation for your XML parsing library to determine how to achieve this.\n\nXML external entity injection makes use of the DOCTYPE tag to define the injected entity. It may also be possible to disable the DOCTYPE tag or use input validation to block input containing it."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "XPath Injection"
		tempSeverity = "High"
		tempIssueDetail = "An XPath Injection vulnerability was discovered."
		tempIssueBackground = "XPath injection vulnerabilities arise when user-controllable data is incorporated into XPath queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.\n\nDepending on the purpose for which the vulnerable query is being used, an attacker may be able to exploit an XPath injection flaw to read sensitive application data or interfere with application logic."
		tempRemediationDetail = ""
		tempRemediationBackground = "User input should be strictly validated before being incorporated into XPath queries. In most cases, it will be appropriate to accept input containing only short alphanumeric strings. At the very least, input containing any XPath metacharacters such as \" ' / @ = * [ ] ( and ) should be rejected."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Cross-Site Request Forgery (CSRF)"
		tempSeverity = "Medium"
		tempIssueDetail = "A Cross-Site Request Forgery (CSRF) vulnerability was discovered."
		tempIssueBackground = "Cross-site request forgery (CSRF) vulnerabilities may arise when applications rely solely on HTTP cookies to identify the user that has issued a particular request. Because browsers automatically add cookies to requests regardless of their origin, it may be possible for an attacker to create a malicious web site that forges a cross-domain request to the vulnerable application. For a request to be vulnerable to CSRF, the following conditions must hold:\n\nThe request can be issued cross-domain, for example using an HTML form. If the request contains non-standard headers or body content, then it may only be issuable from a page that originated on the same domain.\n\nThe application relies solely on HTTP cookies or Basic Authentication to identify the user that issued the request. If the application places session-related tokens elsewhere within the request, then it may not be vulnerable.\n\nThe request performs some privileged action within the application, which modifies the application's state based on the identity of the issuing user.\n\nThe attacker can determine all the parameters required to construct a request that performs the action. If the request contains any values that the attacker cannot determine or predict, then it is not vulnerable."
		tempRemediationDetail = ""
		tempRemediationBackground = "The most effective way to protect against CSRF vulnerabilities is to include within relevant requests an additional token that is not transmitted in a cookie: for example, a parameter in a hidden form field. This additional token should contain sufficient entropy, and be generated using a cryptographic random number generator, such that it is not feasible for an attacker to determine or predict the value of any token that was issued to another user. The token should be associated with the user's session, and the application should validate that the correct token is received before performing any action resulting from the request.\n\nAn alternative approach, which may be easier to implement, is to validate that Host and Referer headers in relevant requests are both present and contain the same domain name. However, this approach is somewhat less robust: historically, quirks in browsers and plugins have often enabled attackers to forge cross-domain requests that manipulate these headers to bypass such defenses."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "XML Injection"
		tempSeverity = "Medium"
		tempIssueDetail = "An XML Injection vulnerability was discovered."
		tempIssueBackground = "XML or SOAP injection vulnerabilities arise when user input is inserted into a server-side XML document or SOAP message in an unsafe way. It may be possible to use XML metacharacters to modify the structure of the resulting XML. Depending on the function in which the XML is used, it may be possible to interfere with the application's logic, to perform unauthorized actions or access sensitive data.\n\nThis kind of vulnerability can be difficult to detect and exploit remotely; you should review the application's response, and the purpose that the relevant input performs within the application's functionality, to determine whether it is indeed vulnerable."
		tempRemediationDetail = ""
		tempRemediationBackground = "The application should validate or sanitize user input before incorporating it into an XML document or SOAP message. It may be possible to block any input containing XML metacharacters such as < and >. Alternatively, these characters can be replaced with the corresponding entities: &lt; and &gt;."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Link Manipulation"
		tempSeverity = "Low"
		tempIssueDetail = "A link was manipulated."
		tempIssueBackground = "Link manipulation occurs when an application embeds user input into the path or domain of URLs that appear within application responses. An attacker can use this vulnerability to construct a link that, if visited by another application user, will modify the target of URLs within the response. It may be possible to leverage this to perform various attacks, such as:\n\nManipulating the path of an on-site link that has sensitive parameters in the URL. If the response from the modified path contains references to off-site resources, then the sensitive data might be leaked to external domains via the Referer header.\n\nManipulating the URL targeted by a form action, making the form submission have unintended side effects.\n\nManipulating the URL used by a CSS import statement to point to an attacker-uploaded file, resulting in CSS injection.\n\nInjecting on-site links containing XSS exploits, thereby bypassing browser anti-XSS defenses, since those defenses typically do not operate on on-site links.\n\nThe security impact of this issue depends largely on the nature of the application functionality. Even if it has no direct impact on its own, an attacker may use it in conjunction with other vulnerabilities to escalate their overall severity."
		tempRemediationDetail = ""
		tempRemediationBackground = "Consider using a whitelist to restrict user input to safe values. Please note that in some situations this issue will have no security impact, meaning no remediation is necessary."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Open Redirection"
		tempSeverity = "Low"
		tempIssueDetail = "An open redirection was discovered."
		tempIssueBackground = "Open redirection vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain. This behavior can be leveraged to facilitate phishing attacks against users of the application. The ability to use an authentic application URL, targeting the correct domain and with a valid SSL certificate (if SSL is used), lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain."
		tempRemediationDetail = ""
		tempRemediationBackground = "If possible, applications should avoid incorporating user-controllable data into redirection targets. In many cases, this behavior can be avoided in two ways:\n\nRemove the redirection function from the application, and replace links to it with direct links to the relevant target URLs.\n\nMaintain a server-side list of all URLs that are permitted for redirection. Instead of passing the target URL as a parameter to the redirector, pass an index into this list.\n\nIf it is considered unavoidable for the redirection function to receive user-controllable input and incorporate this into the redirection target, one of the following measures should be used to minimize the risk of redirection attacks:\n\nThe application should use relative URLs in all of its redirects, and the redirection function should strictly validate that the URL received is a relative URL.\n\nThe application should use URLs relative to the web root for all of its redirects, and the redirection function should validate that the URL received starts with a slash character. It should then prepend http://yourdomainname.com to the URL before issuing the redirect.\n\nThe application should use absolute URLs for all of its redirects, and the redirection function should verify that the user-supplied URL begins with http://yourdomainname.com/ before issuing the redirect."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Password Submitted Using GET Method"
		tempSeverity = "Low"
		tempIssueDetail = "A password was submitted using the GET method."
		tempIssueBackground = "Some applications use the GET method to submit passwords, which are transmitted within the query string of the requested URL. Sensitive information within URLs may be logged in various locations, including the user's browser, the web server, and any forward or reverse proxy servers between the two endpoints. URLs may also be displayed on-screen, bookmarked or emailed around by users. They may be disclosed to third parties via the Referer header when any off-site links are followed. Placing passwords into the URL increases the risk that they will be captured by an attacker.\n\nVulnerabilities that result in the disclosure of users' passwords can result in compromises that are extremely difficult to investigate due to obscured audit trails. Even if the application itself only handles non-sensitive information, exposing passwords puts users who have re-used their password elsewhere at risk."
		tempRemediationDetail = ""
		tempRemediationBackground = "All forms submitting passwords should use the POST method. To achieve this, applications should specify the method attribute of the FORM tag as method=\"POST\". It may also be necessary to modify the corresponding server-side form handler to ensure that submitted passwords are properly retrieved from the message body, rather than the URL."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Base64-Encoded Data In Parameter"
		tempSeverity = "Information"
		tempIssueDetail = "A Base64-encoded parameter was discovered."
		tempIssueBackground = "Applications sometimes Base64-encode parameters in an attempt to obfuscate them from users or facilitate transport of binary data. The presence of Base64-encoded data may indicate security-sensitive information or functionality that is worthy of further investigation. The data should be reviewed to determine whether it contains any interesting information, or provides any additional entry points for malicious input."
		tempRemediationDetail = ""
		tempRemediationBackground = "Confirm that the Base64-encoded parameters do not contain sensitive information."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "File Upload Functionality"
		tempSeverity = "Information"
		tempIssueDetail = "File upload functionality was discovered."
		tempIssueBackground = "File upload functionality is commonly associated with a number of vulnerabilities, including:\nFile path traversal\nPersistent cross-site scripting\nPlacing of other client-executable code into the domain\nTransmission of viruses and other malware\nDenial of service\n\nYou should review file upload functionality to understand its purpose, and establish whether uploaded content is ever returned to other application users, either through their normal usage of the application or by being fed a specific link by an attacker.\n\nSome factors to consider when evaluating the security impact of this functionality include:\n\nWhether uploaded content can subsequently be downloaded via a URL within the application.\n\nWhat Content-type and Content-disposition headers the application returns when the file's content is downloaded.\n\nWhether it is possible to place executable HTML/JavaScript into the file, which executes when the file's contents are viewed.\n\nWhether the application performs any filtering on the file extension or MIME type of the uploaded file.\n\nWhether it is possible to construct a hybrid file containing both executable and non-executable content, to bypass any content filters - for example, a file containing both a GIF image and a Java archive (known as a GIFAR file).\n\nWhat location is used to store uploaded content, and whether it is possible to supply a crafted filename to escape from this location.\n\nWhether archive formats such as ZIP are unpacked by the application.\n\nHow the application handles attempts to upload very large files, or decompression bomb files."
		tempRemediationDetail = ""
		tempRemediationBackground = "File upload functionality is not straightforward to implement securely. Some recommendations to consider in the design of this functionality include:\n\nUse a server-generated filename if storing uploaded files on disk.\n\nInspect the content of uploaded files, and enforce a whitelist of accepted, non-executable content types. Additionally, enforce a blacklist of common executable formats, to hinder hybrid file attacks.\n\nEnforce a whitelist of accepted, non-executable file extensions.\n\nIf uploaded files are downloaded by users, supply an accurate non-generic Content-Type header, the X-Content-Type-Options: nosniff header, and also a Content-Disposition header that specifies that browsers should handle the file as an attachment.\n\nEnforce a size limit on uploaded files (for defense-in-depth, this can be implemented both within application code and in the web server's configuration).\n\nReject attempts to upload archive formats such as ZIP."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Information Leakage"
		tempSeverity = "Information"
		tempIssueDetail = "Information Leakage was discovered."
		tempIssueBackground = "Applications sometimes leak information. This information could contain sensitive data or be used by an attacker to exploit the application."
		tempRemediationDetail = ""
		tempRemediationBackground = "Applications should not leak information."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Information Leakage (Document Metadata)"
		tempSeverity = "Information"
		tempIssueDetail = "Information Leakage was discovered in document metadata."
		tempIssueBackground = "Documents sometimes leak information in the document metadata. This information can be quite useful to attackers and can be used to perform attacks including password attacks and social engineering attacks."
		tempRemediationDetail = ""
		tempRemediationBackground = "Documents should not leak information from the document metadata. Remove metadata from documents."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Information Leakage (Improper Error Handling)"
		tempSeverity = "Information"
		tempIssueDetail = "Information Leakage was discovered in an error message."
		tempIssueBackground = "Applications sometimes leak information in error messages displayed to end users. These error messages can be quite useful to attackers and may be useful in exploiting a vulnerability."
		tempRemediationDetail = ""
		tempRemediationBackground = "Applications should not leak information from the error messages."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Input Returned In Response"
		tempSeverity = "Information"
		tempIssueDetail = "User input was returned in a response."
		tempIssueBackground = "User input was echoed into the application's response.\n\nInput being returned in application responses is not a vulnerability in its own right. However, it is a prerequisite for many client-side vulnerabilities, including cross-site scripting, open redirection, content spoofing, and response header injection. Additionally, some server-side vulnerabilities such as SQL injection are often easier to identify and exploit when input is returned in responses. In applications where input retrieval is rare and the environment is resistant to automated testing (for example, due to a web application firewall), it might be worth subjecting instances of it to focused manual testing."
		tempRemediationDetail = ""
		tempRemediationBackground = "Confirm that the input that was echoed cannot be used by an attacker to exploit a vulnerability."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Interesting Parameter Passed To Web Page"
		tempSeverity = "Information"
		tempIssueDetail = "An interesting parameter was passed to a web page."
		tempIssueBackground = "An interesting parameter was passed to a web page."
		tempRemediationDetail = ""
		tempRemediationBackground = "Confirm that the parameter passed to the web page is by design and cannot be used to exploit a vulnerability."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Long Redirection Response"
		tempSeverity = "Information"
		tempIssueDetail = "A long redirection response was discovered."
		tempIssueBackground = "The application returned a redirection response containing a \"long\" message body. Ordinarily, this content is not displayed to the user, because the browser automatically follows the redirection.\n\nOccasionally, redirection responses contain sensitive data. For example, if the user requests a page that they are not authorized to view, then an application might issue a redirection to a different page, but also include the contents of the prohibited page.\n\nYou should review the contents of the response to determine whether it contains anything sensitive."
		tempRemediationDetail = ""
		tempRemediationBackground = "In cases where the application handles requests for unauthorized content by redirecting to a different URL, the application should ensure that no sensitive content is included within the redirection response. Depending on the application and the platform, this might involve checking for proper authorization earlier in the request handling logic, or using a different API to perform the redirection."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Open Ports"
		tempSeverity = "Information"
		tempIssueDetail = "ENTER_OPEN_PORTS_HERE"
		tempIssueBackground = "The open ports were discovered by ENTER_DISCOVERY_METHOD_HERE"
		tempRemediationDetail = ""
		tempRemediationBackground = "Confirm that the port(s) listed should be open."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Robots.txt File Output"
		tempSeverity = "Information"
		tempIssueDetail = "ENTER_ROBOTS.TXT_OUTPUT_HERE"
		tempIssueBackground = "The file robots.txt is used to give instructions to web robots, such as search engine crawlers, about locations within the web site that robots are allowed, or not allowed, to crawl and index.\n\nThe presence of the robots.txt does not in itself present any kind of security vulnerability. However, it is often used to identify restricted or private areas of a site's contents. The information in the file may therefore help an attacker to map out the site's contents, especially if some of the locations identified are not linked from elsewhere in the site. If the application relies on robots.txt to protect access to these areas, and does not enforce proper access control over them, then this presents a serious vulnerability."
		tempRemediationDetail = ""
		tempRemediationBackground = "The robots.txt file is not itself a security threat, and its correct use can represent good practice for non-security reasons. You should not assume that all web robots will honor the file's instructions. Rather, assume that attackers will pay close attention to any locations identified in the file. Do not rely on robots.txt to provide any kind of protection over unauthorized access."
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "DirBuster Results"
		tempSeverity = "Information"
		tempIssueDetail = "ENTER_OUTPUT_HERE"
		tempIssueBackground = "The command used was: ENTER_DIRBUSTER_COMMAND_USED_HERE"
		tempRemediationDetail = ""
		tempRemediationBackground = ""
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "DotDotPwn Results"
		tempSeverity = "Information"
		tempIssueDetail = "ENTER_OUTPUT_HERE"
		tempIssueBackground = "The command used was: ENTER_DOTDOTPWN_COMMAND_USED_HERE"
		tempRemediationDetail = ""
		tempRemediationBackground = ""
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Nikto Results"
		tempSeverity = "Information"
		tempIssueDetail = "ENTER_OUTPUT_HERE"
		tempIssueBackground = "The command used was: ENTER_NIKTO_COMMAND_USED_HERE"
		tempRemediationDetail = ""
		tempRemediationBackground = ""
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Nmap Results"
		tempSeverity = "Information"
		tempIssueDetail = "ENTER_OUTPUT_HERE"
		tempIssueBackground = "The command used was: ENTER_NMAP_COMMAND_USED_HERE"
		tempRemediationDetail = ""
		tempRemediationBackground = ""
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "SQLMap Results"
		tempSeverity = "Information"
		tempIssueDetail = "ENTER_OUTPUT_HERE"
		tempIssueBackground = "The command used was: ENTER_SQLMAP_COMMAND_USED_HERE"
		tempRemediationDetail = ""
		tempRemediationBackground = ""
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		tempIssueName = "Wfuzz Results"
		tempSeverity = "Information"
		tempIssueDetail = "ENTER_OUTPUT_HERE"
		tempIssueBackground = "The command used was: ENTER_WFUZZ_COMMAND_USED_HERE"
		tempRemediationDetail = ""
		tempRemediationBackground = ""
		self.extender._tableModelShared.addRow([tempIssueName, tempSeverity, tempIssueDetail, tempIssueBackground, tempRemediationDetail, tempRemediationBackground])

		return

