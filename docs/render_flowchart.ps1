Add-Type -AssemblyName System.Drawing

function Draw-CryptoShieldWorkflow {
    param (
        [string]$OutputFile,
        [string]$Format = "PNG"
    )

    $w = 2360
    $h = 1680

    $bmp = New-Object System.Drawing.Bitmap $w, $h
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

    # Dark background matching Antigravity IDE UI
    $bgBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(18, 20, 26))
    $g.FillRectangle($bgBrush, 0, 0, $w, $h)

    # Fonts
    $titleFont = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $subtitleFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)
    $actorFont = New-Object System.Drawing.Font("Segoe UI", 10.5, [System.Drawing.FontStyle]::Bold)
    $stepFont = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $noteFont = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $badgeFont = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)

    # Brushes & Pens
    $textBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(241, 245, 249))
    $subtextBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(148, 163, 184))
    $cyanBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(56, 189, 248))
    $greenBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(74, 222, 128))
    $redBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(248, 113, 113))
    $amberBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(251, 191, 36))

    # Title header
    $g.DrawString("CryptoShield — End-to-End Defensive Lifecycle Workflow", $titleFont, $cyanBrush, 50, 24)
    $g.DrawString("Autonomous Double-Extortion Ransomware Containment, DLP Pre-Flight Interception & Authenticated Recovery", $subtitleFont, $subtextBrush, 52, 60)

    # Actors definition
    $actors = @(
        @{ Name = "Attacker /`nRansomware"; X = 150 },
        @{ Name = "Lab Filesystem`n(20,000 files)"; X = 430 },
        @{ Name = "Monitoring`n(FS + Process)"; X = 710 },
        @{ Name = "Exfiltration`n& DLP Gate"; X = 990 },
        @{ Name = "Threat Scorer`n& Incident Mgr"; X = 1270 },
        @{ Name = "Containment`n(Gate & Killer)"; X = 1550 },
        @{ Name = "Crypto Vault`n(AES-GCM/RSA)"; X = 1830 },
        @{ Name = "Recovery`nEngine"; X = 2110 }
    )

    $actorBoxW = 190
    $actorBoxH = 54
    $topY = 100
    $bottomY = 1570

    # Draw Actor Lifelines (vertical dashed lines)
    $lifePen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(71, 85, 105), 1.5)
    $lifePen.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash

    foreach ($act in $actors) {
        $cx = $act.X
        $g.DrawLine($lifePen, $cx, $topY + $actorBoxH, $cx, $bottomY)
    }

    # Helper function to draw rounded card
    function Draw-Card ($x, $y, $w, $h, $bgClr, $borderClr, $radius=8) {
        $path = New-Object System.Drawing.Drawing2D.GraphicsPath
        $d = $radius * 2
        $path.AddArc($x, $y, $d, $d, 180, 90)
        $path.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
        $path.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
        $path.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
        $path.CloseFigure()

        $fillB = New-Object System.Drawing.SolidBrush $bgClr
        $g.FillPath($fillB, $path)
        $fillB.Dispose()

        if ($borderClr -ne $null) {
            $p = New-Object System.Drawing.Pen $borderClr, 1.2
            $g.DrawPath($p, $path)
            $p.Dispose()
        }
        $path.Dispose()
    }

    # Draw Actor Boxes at top and bottom
    $actBg = [System.Drawing.Color]::FromArgb(30, 41, 59)
    $actBorder = [System.Drawing.Color]::FromArgb(56, 189, 248)

    foreach ($act in $actors) {
        $bx = $act.X - ($actorBoxW / 2)
        # Top box
        Draw-Card $bx $topY $actorBoxW $actorBoxH $actBg $actBorder 8
        # Bottom box
        Draw-Card $bx $bottomY $actorBoxW $actorBoxH $actBg $actBorder 8

        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = [System.Drawing.StringAlignment]::Center
        $sf.LineAlignment = [System.Drawing.StringAlignment]::Center

        $rectTop = New-Object System.Drawing.RectangleF $bx, $topY, $actorBoxW, $actorBoxH
        $rectBottom = New-Object System.Drawing.RectangleF $bx, $bottomY, $actorBoxW, $actorBoxH

        $g.DrawString($act.Name, $actorFont, $textBrush, $rectTop, $sf)
        $g.DrawString($act.Name, $actorFont, $textBrush, $rectBottom, $sf)
        $sf.Dispose()
    }

    # Helper function to draw an arrow with text label & number badge
    function Draw-Arrow ($x1, $x2, $y, $label, $badgeNum, $color, $isDashed=$false, $isBlocked=$false) {
        $p = New-Object System.Drawing.Pen $color, 2.0
        if ($isDashed) {
            $p.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
        }
        
        $dir = if ($x2 -ge $x1) { 1 } else { -1 }
        $arrowTipX = $x2 - ($dir * 6)
        
        $g.DrawLine($p, $x1, $y, $arrowTipX, $y)

        # Draw arrowhead
        $arrowBrush = New-Object System.Drawing.SolidBrush $color
        $arrowPath = New-Object System.Drawing.Drawing2D.GraphicsPath
        if ($isBlocked) {
            # Draw red cross / barrier
            $crossPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(239, 68, 68)), 3.0
            $g.DrawLine($crossPen, $x2 - 8, $y - 8, $x2 + 8, $y + 8)
            $g.DrawLine($crossPen, $x2 - 8, $y + 8, $x2 + 8, $y - 8)
            $crossPen.Dispose()
        } else {
            $arrowSize = 6
            $p1 = New-Object System.Drawing.PointF ($x2), $y
            $p2 = New-Object System.Drawing.PointF ($x2 - $dir * 12), ($y - $arrowSize)
            $p3 = New-Object System.Drawing.PointF ($x2 - $dir * 12), ($y + $arrowSize)
            $arrowPath.AddPolygon(@($p1, $p2, $p3))
            $g.FillPath($arrowBrush, $arrowPath)
        }
        $arrowPath.Dispose()
        $arrowBrush.Dispose()
        $p.Dispose()

        # Draw Badge & Label
        $midX = ($x1 + $x2) / 2
        $labelFont = $stepFont

        if ($badgeNum -ne $null) {
            # Circular badge
            $badgeRadius = 10
            $badgeX = $midX - 110
            $badgeY = $y - 10
            
            $bBg = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(15, 23, 42))
            $bBorder = New-Object System.Drawing.Pen $color, 1.5
            $g.FillEllipse($bBg, $badgeX - $badgeRadius, $badgeY - $badgeRadius, $badgeRadius * 2, $badgeRadius * 2)
            $g.DrawEllipse($bBorder, $badgeX - $badgeRadius, $badgeY - $badgeRadius, $badgeRadius * 2, $badgeRadius * 2)
            
            $sf = New-Object System.Drawing.StringFormat
            $sf.Alignment = [System.Drawing.StringAlignment]::Center
            $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
            $g.DrawString($badgeNum.ToString(), $badgeFont, $cyanBrush, $badgeX, $badgeY, $sf)
            $sf.Dispose()
            $bBg.Dispose()
            $bBorder.Dispose()

            # Text label
            $textX = $badgeX + 16
            $g.DrawString($label, $labelFont, $textBrush, $textX, $y - 16)
        } else {
            # Text label centered
            $sf = New-Object System.Drawing.StringFormat
            $sf.Alignment = [System.Drawing.StringAlignment]::Center
            $g.DrawString($label, $labelFont, $textBrush, $midX, $y - 18, $sf)
            $sf.Dispose()
        }
    }

    # Helper function to draw note banner across columns
    function Draw-Note ($xStart, $xEnd, $y, $text, $bgClr, $textClr, $borderClr) {
        $nw = $xEnd - $xStart
        $nh = 34
        $nx = $xStart
        $ny = $y - ($nh / 2)
        Draw-Card $nx $ny $nw $nh $bgClr $borderClr 6

        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = [System.Drawing.StringAlignment]::Center
        $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
        $rect = New-Object System.Drawing.RectangleF $nx, $ny, $nw, $nh
        $tBrush = New-Object System.Drawing.SolidBrush $textClr
        $g.DrawString($text, $noteFont, $tBrush, $rect, $sf)
        $tBrush.Dispose()
        $sf.Dispose()
    }

    # Step Colors
    $cNormal = [System.Drawing.Color]::FromArgb(148, 163, 184)
    $cCyan = [System.Drawing.Color]::FromArgb(56, 189, 248)
    $cGreen = [System.Drawing.Color]::FromArgb(74, 222, 128)
    $cRed = [System.Drawing.Color]::FromArgb(248, 113, 113)
    $cAmber = [System.Drawing.Color]::FromArgb(251, 191, 36)

    # Coordinates shorthand
    $xAttacker = 150
    $xLab = 430
    $xMon = 710
    $xExfil = 990
    $xScorer = 1270
    $xContain = 1550
    $xVault = 1830
    $xRecovery = 2110

    # -------------------------------------------------------------
    # 0. Peacetime Note
    # -------------------------------------------------------------
    Draw-Note $xLab $xVault 195 "PEACETIME: System creates Baseline Manifest (SHA-256) & Encrypted Snapshot (AES-GCM/RSA)" `
        ([System.Drawing.Color]::FromArgb(12, 74, 110)) ([System.Drawing.Color]::FromArgb(186, 230, 253)) ([System.Drawing.Color]::FromArgb(56, 189, 248))

    # -------------------------------------------------------------
    # Exfiltration Phase (Steps 1 to 8)
    # -------------------------------------------------------------
    # 1. Attacker -> Lab: Mass file harvesting
    Draw-Arrow $xAttacker $xLab 250 "1. Mass file harvesting across departments" "1" $cNormal

    # 2. Monitoring -> Threat Scorer: Read burst detected!
    Draw-Arrow $xMon $xScorer 305 "2. Read burst detected!" "2" $cAmber

    # 3. Attacker -> Lab: Compresses stolen files into stage.zip
    Draw-Arrow $xAttacker $xLab 360 "3. Compresses stolen files into stage.zip" "3" $cNormal

    # 4. Monitoring -> Threat Scorer: Staging archive detected!
    Draw-Arrow $xMon $xScorer 415 "4. Staging archive detected!" "4" $cAmber

    # 5. Attacker -> Exfil: Tries to transmit stage.zip over network
    Draw-Arrow $xAttacker $xExfil 470 "5. Tries to transmit stage.zip over network" "5" $cAmber

    # 6. DLP Gate inspects: RESTRICTED files found! (Self-check card on Exfil)
    Draw-Note ($xExfil - 140) ($xExfil + 140) 525 "6. DLP Gate inspects: RESTRICTED files found!" `
        ([System.Drawing.Color]::FromArgb(69, 26, 3)) ([System.Drawing.Color]::FromArgb(254, 215, 170)) ([System.Drawing.Color]::FromArgb(249, 115, 22))

    # 7. Exfil -> Attacker: BLOCKED! 0 bytes transmitted.
    Draw-Arrow $xExfil $xAttacker 580 "7. BLOCKED! 0 bytes transmitted." "7" $cRed $true $true

    # 8. Exfil -> Threat Scorer: Exfiltration Threat = CRITICAL
    Draw-Arrow $xExfil $xScorer 635 "8. Exfiltration Threat = CRITICAL" "8" $cRed

    # -------------------------------------------------------------
    # Ransomware & Containment Phase (Steps 9 to 15)
    # -------------------------------------------------------------
    # 9. Attacker -> Lab: Begins mass encryption & modifies Canary file
    Draw-Arrow $xAttacker $xLab 700 "9. Begins mass encryption & modifies Canary file" "9" $cRed

    # 10. Monitoring -> Threat Scorer: CANARY_ACCESS + High-frequency file rewrites!
    Draw-Arrow $xMon $xScorer 755 "10. CANARY_ACCESS + High-frequency file rewrites!" "10" $cRed

    # 11. Threat Scorer card: Threat Score = 100 (CRITICAL)
    Draw-Note ($xScorer - 135) ($xScorer + 135) 810 "11. Threat Score = 100 (CRITICAL)" `
        ([System.Drawing.Color]::FromArgb(69, 10, 10)) ([System.Drawing.Color]::FromArgb(254, 202, 202)) ([System.Drawing.Color]::FromArgb(239, 68, 68))

    # 12. Threat Scorer -> Containment: Trigger Emergency Containment!
    Draw-Arrow $xScorer $xContain 865 "12. Trigger Emergency Containment!" "12" $cRed

    # 13. Containment -> Lab: Closes LabWriteGate (.write_gate_state)
    Draw-Arrow $xContain $xLab 920 "13. Closes LabWriteGate (.write_gate_state)" "13" $cAmber

    # 14. Containment -> Attacker: Terminates malicious process handle
    Draw-Arrow $xContain $xAttacker 975 "14. Terminates malicious process handle" "14" $cRed $false $true

    # 15. Containment -> Threat Scorer: Containment Verified & Locked
    Draw-Arrow $xContain $xScorer 1030 "15. Containment Verified & Locked" "15" $cGreen

    # -------------------------------------------------------------
    # Recovery Phase (Steps 16 to 21)
    # -------------------------------------------------------------
    # Banner Note
    Draw-Note $xLab $xRecovery 1095 "INCIDENT RESOLVED: Beginning Cryptographic Recovery (Two-Stage Verified Commit)" `
        ([System.Drawing.Color]::FromArgb(6, 78, 59)) ([System.Drawing.Color]::FromArgb(167, 243, 208)) ([System.Drawing.Color]::FromArgb(16, 185, 129))

    # 16. Recovery Engine -> Lab: Scans disk vs Manifest (Flags missing & encrypted files)
    Draw-Arrow $xRecovery $xLab 1160 "16. Scans disk vs Manifest (Flags missing & encrypted files)" "16" $cGreen

    # 17. Recovery Engine -> Crypto Vault: Requests clean snapshot objects (.cso)
    Draw-Arrow $xRecovery $xVault 1220 "17. Requests clean snapshot objects (.cso)" "17" $cCyan

    # 18. Crypto Vault -> Recovery Engine: Decrypts & verifies SHA-256 + GCM Auth Tag
    Draw-Arrow $xVault $xRecovery 1280 "18. Decrypts & verifies SHA-256 + GCM Auth Tag" "18" $cCyan

    # 19. Recovery Engine -> Lab: Atomically restores original files bit-for-bit!
    Draw-Arrow $xRecovery $xLab 1340 "19. Atomically restores original files bit-for-bit!" "19" $cGreen

    # 20. Result Note
    Draw-Note $xLab ($xLab + 340) 1405 "20. 100% Files Restored (Intact) | 0 Bytes Leaked" `
        ([System.Drawing.Color]::FromArgb(6, 78, 59)) ([System.Drawing.Color]::FromArgb(167, 243, 208)) ([System.Drawing.Color]::FromArgb(16, 185, 129))

    # Save to disk
    $imgFormat = if ($Format -eq "JPEG" -or $Format -eq "JPG") {
        [System.Drawing.Imaging.ImageFormat]::Jpeg
    } else {
        [System.Drawing.Imaging.ImageFormat]::Png
    }

    $bmp.Save($OutputFile, $imgFormat)

    # Cleanup
    $g.Dispose()
    $bmp.Dispose()
    $bgBrush.Dispose()
    $textBrush.Dispose()
    $subtextBrush.Dispose()
    $cyanBrush.Dispose()
    $greenBrush.Dispose()
    $redBrush.Dispose()
    $amberBrush.Dispose()
    $titleFont.Dispose()
    $subtitleFont.Dispose()
    $actorFont.Dispose()
    $stepFont.Dispose()
    $noteFont.Dispose()
    $badgeFont.Dispose()
    $lifePen.Dispose()

    Write-Output "Successfully generated: $OutputFile"
}

# Generate both PNG and JPEG formats
Draw-CryptoShieldWorkflow -OutputFile (Join-Path $PSScriptRoot "CryptoShield_Workflow_Diagram.png") -Format "PNG"
Draw-CryptoShieldWorkflow -OutputFile (Join-Path $PSScriptRoot "CryptoShield_Workflow_Diagram.jpg") -Format "JPEG"
