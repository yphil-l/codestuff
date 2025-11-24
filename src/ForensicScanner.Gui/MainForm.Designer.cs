namespace ForensicScanner.Gui;

partial class MainForm
{
    private System.ComponentModel.IContainer components = null!;
    private GroupBox grpDepth = null!;
    private RadioButton radioLight = null!;
    private RadioButton radioMedium = null!;
    private RadioButton radioDeep = null!;
    private Label lblCustomRegistry = null!;
    private TextBox txtCustomRegistryKeys = null!;
    private Label lblCustomFiles = null!;
    private TextBox txtCustomFilePaths = null!;
    private Button btnStartScan = null!;
    private Button btnCancelScan = null!;
    private Button btnSaveReport = null!;
    private ProgressBar progressBar = null!;
    private Label lblStatus = null!;
    private RichTextBox resultsTextBox = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing && components != null)
        {
            components.Dispose();
        }
        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        components = new System.ComponentModel.Container();
        grpDepth = new GroupBox();
        radioLight = new RadioButton();
        radioMedium = new RadioButton();
        radioDeep = new RadioButton();
        lblCustomRegistry = new Label();
        txtCustomRegistryKeys = new TextBox();
        lblCustomFiles = new Label();
        txtCustomFilePaths = new TextBox();
        btnStartScan = new Button();
        btnCancelScan = new Button();
        btnSaveReport = new Button();
        progressBar = new ProgressBar();
        lblStatus = new Label();
        resultsTextBox = new RichTextBox();
        grpDepth.SuspendLayout();
        SuspendLayout();
        
        // grpDepth
        grpDepth.Controls.Add(radioDeep);
        grpDepth.Controls.Add(radioMedium);
        grpDepth.Controls.Add(radioLight);
        grpDepth.Location = new Point(12, 12);
        grpDepth.Name = "grpDepth";
        grpDepth.Size = new Size(300, 100);
        grpDepth.TabIndex = 0;
        grpDepth.TabStop = false;
        grpDepth.Text = "Scan Depth";
        
        // radioLight
        radioLight.AutoSize = true;
        radioLight.Checked = true;
        radioLight.Location = new Point(15, 25);
        radioLight.Name = "radioLight";
        radioLight.Size = new Size(144, 19);
        radioLight.TabIndex = 0;
        radioLight.TabStop = true;
        radioLight.Text = "Light (Quick checks)";
        radioLight.UseVisualStyleBackColor = true;
        
        // radioMedium
        radioMedium.AutoSize = true;
        radioMedium.Location = new Point(15, 50);
        radioMedium.Name = "radioMedium";
        radioMedium.Size = new Size(191, 19);
        radioMedium.TabIndex = 1;
        radioMedium.Text = "Medium (+ Amcache, USN, BAM)";
        radioMedium.UseVisualStyleBackColor = true;
        
        // radioDeep
        radioDeep.AutoSize = true;
        radioDeep.Location = new Point(15, 75);
        radioDeep.Name = "radioDeep";
        radioDeep.Size = new Size(209, 19);
        radioDeep.TabIndex = 2;
        radioDeep.Text = "Deep (+ VSS, ADS, memory scan)";
        radioDeep.UseVisualStyleBackColor = true;
        
        // lblCustomRegistry
        lblCustomRegistry.AutoSize = true;
        lblCustomRegistry.Location = new Point(12, 125);
        lblCustomRegistry.Name = "lblCustomRegistry";
        lblCustomRegistry.Size = new Size(273, 15);
        lblCustomRegistry.TabIndex = 1;
        lblCustomRegistry.Text = "Custom Registry Keys (comma or newline separated):";
        
        // txtCustomRegistryKeys
        txtCustomRegistryKeys.Location = new Point(12, 143);
        txtCustomRegistryKeys.Multiline = true;
        txtCustomRegistryKeys.ScrollBars = ScrollBars.Vertical;
        txtCustomRegistryKeys.Size = new Size(300, 80);
        txtCustomRegistryKeys.TabIndex = 2;
        
        // lblCustomFiles
        lblCustomFiles.AutoSize = true;
        lblCustomFiles.Location = new Point(12, 226);
        lblCustomFiles.Name = "lblCustomFiles";
        lblCustomFiles.Size = new Size(274, 15);
        lblCustomFiles.TabIndex = 3;
        lblCustomFiles.Text = "Custom File/Directory Paths (comma or newline separated):";
        
        // txtCustomFilePaths
        txtCustomFilePaths.Location = new Point(12, 244);
        txtCustomFilePaths.Multiline = true;
        txtCustomFilePaths.ScrollBars = ScrollBars.Vertical;
        txtCustomFilePaths.Size = new Size(300, 80);
        txtCustomFilePaths.TabIndex = 4;
        
        // btnStartScan
        btnStartScan.Location = new Point(12, 330);
        btnStartScan.Name = "btnStartScan";
        btnStartScan.Size = new Size(90, 30);
        btnStartScan.TabIndex = 5;
        btnStartScan.Text = "Start Scan";
        btnStartScan.UseVisualStyleBackColor = true;
        btnStartScan.Click += BtnStartScan_Click;
        
        // btnCancelScan
        btnCancelScan.Location = new Point(108, 330);
        btnCancelScan.Name = "btnCancelScan";
        btnCancelScan.Size = new Size(90, 30);
        btnCancelScan.TabIndex = 6;
        btnCancelScan.Text = "Cancel";
        btnCancelScan.UseVisualStyleBackColor = true;
        btnCancelScan.Click += BtnCancelScan_Click;
        btnCancelScan.Enabled = false;
        
        // btnSaveReport
        btnSaveReport.Location = new Point(204, 330);
        btnSaveReport.Name = "btnSaveReport";
        btnSaveReport.Size = new Size(108, 30);
        btnSaveReport.TabIndex = 7;
        btnSaveReport.Text = "Save Report";
        btnSaveReport.UseVisualStyleBackColor = true;
        btnSaveReport.Click += BtnSaveReport_Click;
        
        // progressBar
        progressBar.Location = new Point(12, 370);
        progressBar.Size = new Size(300, 20);
        progressBar.TabIndex = 8;
        
        // lblStatus
        lblStatus.AutoSize = true;
        lblStatus.Location = new Point(12, 395);
        lblStatus.Name = "lblStatus";
        lblStatus.Size = new Size(94, 15);
        lblStatus.TabIndex = 9;
        lblStatus.Text = "Status: Waiting...";
        
        // resultsTextBox
        resultsTextBox.Location = new Point(325, 12);
        resultsTextBox.Name = "resultsTextBox";
        resultsTextBox.ReadOnly = true;
        resultsTextBox.Size = new Size(550, 403);
        resultsTextBox.TabIndex = 10;
        resultsTextBox.Text = string.Empty;

        // MainForm
        AutoScaleDimensions = new SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(890, 430);
        Controls.Add(resultsTextBox);
        Controls.Add(lblStatus);
        Controls.Add(progressBar);
        Controls.Add(btnSaveReport);
        Controls.Add(btnCancelScan);
        Controls.Add(btnStartScan);
        Controls.Add(txtCustomFilePaths);
        Controls.Add(lblCustomFiles);
        Controls.Add(txtCustomRegistryKeys);
        Controls.Add(lblCustomRegistry);
        Controls.Add(grpDepth);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        Name = "MainForm";
        StartPosition = FormStartPosition.CenterScreen;
        Text = "Windows Forensic Scanner";
        grpDepth.ResumeLayout(false);
        grpDepth.PerformLayout();
        ResumeLayout(false);
        PerformLayout();
    }
}
