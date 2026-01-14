Attribute VB_Name = "Module1"
Sub DetecterMenaces()
    ' --- 1. CONFIGURATION ET VARIABLES ---
    Dim wsData As Worksheet, wsRapport As Worksheet
    Dim lastRow As Long, i As Long
    Dim dictSyn As Object, dictScan As Object
    Dim ipSrc As String, dstPort As String, flags As String
    Dim colIP As Integer, colPort As Integer, colFlag As Integer
    Dim key As Variant
    
    ' Seuils (identiques à ton Python)
    Const LIMIT_SYN_MID As Integer = 25
    Const LIMIT_SYN_HIGH As Integer = 50
    Const LIMIT_SCAN_PORTS As Integer = 10
    Const LIMIT_SCAN_MAX As Integer = 40
    
    Set wsData = ActiveSheet
    
    ' Création des dictionnaires (Late binding pour éviter les erreurs de références)
    Set dictSyn = CreateObject("Scripting.Dictionary") ' Stocke le nombre de SYN par IP
    Set dictScan = CreateObject("Scripting.Dictionary") ' Stocke un sous-dictionnaire de ports par IP
    
    Application.ScreenUpdating = False
    
    ' --- 2. IDENTIFICATION DES COLONNES ---
    ' On cherche les colonnes par leur nom (comme dans ton CSV généré)
    On Error Resume Next
    colIP = wsData.Rows(1).Find("Source_IP").Column
    colPort = wsData.Rows(1).Find("Dest_Port").Column
    colFlag = wsData.Rows(1).Find("Flags").Column
    On Error GoTo 0
    
    If colIP = 0 Or colPort = 0 Or colFlag = 0 Then
        MsgBox "Impossible de trouver les colonnes 'Source_IP', 'Dest_Port' ou 'Flags'.", vbCritical
        Exit Sub
    End If
    
    lastRow = wsData.Cells(wsData.Rows.count, colIP).End(xlUp).Row
    
    ' --- 3. ANALYSE DES DONNÉES (BOUCLE) ---
    For i = 2 To lastRow
        ipSrc = Trim(wsData.Cells(i, colIP).Value)
        dstPort = Trim(wsData.Cells(i, colPort).Value)
        flags = Trim(wsData.Cells(i, colFlag).Value)
        
        If ipSrc <> "" Then
            ' A) Logique SYN FLOOD
            ' Si le flag contient "S"
            If InStr(1, flags, "S", vbTextCompare) > 0 Then
                If Not dictSyn.Exists(ipSrc) Then
                    dictSyn(ipSrc) = 1
                Else
                    dictSyn(ipSrc) = dictSyn(ipSrc) + 1
                End If
            End If
            
            ' B) Logique PORT SCAN
            ' On vérifie que le port existe
            If dstPort <> "" Then
                If Not dictScan.Exists(ipSrc) Then
                    ' Créer un sous-dictionnaire pour cette IP
                    Set dictScan(ipSrc) = CreateObject("Scripting.Dictionary")
                End If
                ' Ajouter le port s'il n'est pas déjà listé pour cette IP (gestion des doublons)
                If Not dictScan(ipSrc).Exists(dstPort) Then
                    dictScan(ipSrc).Add dstPort, 1
                End If
            End If
        End If
    Next i
    
    ' --- 4. GÉNÉRATION DU RAPPORT ---
    Set wsRapport = Sheets.Add
    wsRapport.Name = "Rapport_Menaces_" & Format(Now, "hhmm")
    
    ' En-têtes
    wsRapport.Range("A1:E1").Value = Array("IP Source", "Type d'Attaque", "Niveau", "Compteur", "Détails")
    wsRapport.Range("A1:E1").Font.Bold = True
    
    Dim r As Long
    r = 2
    
    ' Vérification SYN FLOOD
    For Each key In dictSyn.Keys
        Dim count As Long
        count = dictSyn(key)
        
        If count >= LIMIT_SYN_MID Then
            wsRapport.Cells(r, 1).Value = key
            wsRapport.Cells(r, 2).Value = "SYN Flood"
            If count >= LIMIT_SYN_HIGH Then
                wsRapport.Cells(r, 3).Value = "HIGH"
                wsRapport.Cells(r, 3).Interior.Color = vbRed
            Else
                wsRapport.Cells(r, 3).Value = "MID"
                wsRapport.Cells(r, 3).Interior.Color = vbYellow
            End If
            wsRapport.Cells(r, 4).Value = count
            wsRapport.Cells(r, 5).Value = count & " paquets SYN détectés"
            r = r + 1
        End If
    Next key
    
    ' Vérification PORT SCAN
    For Each key In dictScan.Keys
        Dim uniquePorts As Long
        uniquePorts = dictScan(key).count
        
        If uniquePorts > LIMIT_SCAN_PORTS Then
            wsRapport.Cells(r, 1).Value = key
            wsRapport.Cells(r, 2).Value = "Port Scan"
            If uniquePorts >= LIMIT_SCAN_MAX Then
                wsRapport.Cells(r, 3).Value = "HIGH"
                wsRapport.Cells(r, 3).Interior.Color = vbRed
            Else
                wsRapport.Cells(r, 3).Value = "MID"
                wsRapport.Cells(r, 3).Interior.Color = vbYellow
            End If
            wsRapport.Cells(r, 4).Value = uniquePorts
            wsRapport.Cells(r, 5).Value = "Scan sur " & uniquePorts & " ports distincts"
            r = r + 1
        End If
    Next key
    
    ' Mise en forme
    wsRapport.Columns("A:E").AutoFit
    Application.ScreenUpdating = True
    
    If r = 2 Then
        MsgBox "Aucune menace détectée selon les critères.", vbInformation
    Else
        MsgBox "Analyse terminée ! " & (r - 2) & " menaces potentielles identifiées.", vbExclamation
    End If

End Sub
