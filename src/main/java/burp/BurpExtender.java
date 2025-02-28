package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import burp.*;  // This will import all Burp interfaces including IExtensionHelpers

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("curl2req");
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        JMenuItem pasteMenuItem = new JMenuItem("Paste curl to request");
        
        pasteMenuItem.addActionListener(e -> {
            try {
                // 获取剪贴板内容
                String curlCommand = getClipboardContent();
                if (curlCommand == null || !curlCommand.trim().startsWith("curl")) {
                    JOptionPane.showMessageDialog(null, "No valid curl command in clipboard");
                    return;
                }


                List<String> headersList = CurlParser.parseCURLtoHeaderList(curlCommand);
                byte[] bodyBytes = CurlParser.parseCURLtoBodyBytes(curlCommand);
                if (headersList == null || bodyBytes == null) {
                    return;
                }


                byte[] httpMessage = helpers.buildHttpMessage(headersList, bodyBytes);
                if (httpMessage == null) {
                    return;
                }

                // select messages
                IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
                if (selectedMessages != null && selectedMessages.length > 0) {
                    // update
                    selectedMessages[0].setRequest(httpMessage);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage());
            }
        });

        menuItems.add(pasteMenuItem);
        return menuItems;
    }

    private String getClipboardContent() {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            String content = (String) clipboard.getData(DataFlavor.stringFlavor);
            System.out.println("Clipboard content: " + content); 
            return content;
        } catch (Exception e) {
            return null;
        }
    }
} 
