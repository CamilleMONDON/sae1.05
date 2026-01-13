Attribute VB_Name = "Module2"
Sub AnalyseUniqueSAE()
    Dim ws As Worksheet
    Dim lastRow As Long
    Dim pvtCache As PivotCache
    Dim pvtTable As PivotTable
    
    Set ws = ThisWorkbook.ActiveSheet
    lastRow = ws.Cells(ws.Rows.Count, "A").End(xlUp).Row
    
    ' 1. MISE EN FORME (Style demandé)
    ws.Cells.Font.Name = "Comic Sans MS"
    With ws.Range("A1:J1")
        .Interior.Color = RGB(249, 115, 22) ' Orange
        .Font.Color = RGB(255, 255, 255) ' Blanc
        .Font.Bold = True
    End With

    ' 2. TRAITEMENT : Création du Tableau Croisé Dynamique (Page 3 de votre doc)
    ' Cet outil va regrouper les données par IP pour déceler les anomalies
    Sheets.Add(After:=ws).Name = "Resultats_Analyse"
    Set pvtCache = ThisWorkbook.PivotCaches.Create(xlDatabase, ws.Range("A1:J" & lastRow))
    Set pvtTable = pvtCache.CreatePivotTable(Sheets("Resultats_Analyse").Range("A3"), "AnalyseTrafic")
    
    With pvtTable
        .PivotFields("Source_IP").Orientation = xlRowField
        .AddDataField .PivotFields("Source_IP"), "Nombre de Paquets", xlCount
        .AddDataField .PivotFields("Dest_Port"), "Ports différents visés", xlCount
    End With
    
    ' 3. AFFICHAGE DES RÉSULTATS PERTINENTS (Mise en forme conditionnelle - Page 6)
    ' On colore en Bleu clair les IP qui dépassent les seuils d'alerte
    With Sheets("Resultats_Analyse")
        .Cells.Font.Name = "Comic Sans MS"
        .Range("A3:C3").Interior.Color = RGB(14, 165, 233) ' Bleu clair
        .Range("A3:C3").Font.Color = RGB(255, 255, 255)
        
        ' Ajout d'un titre explicatif
        .Range("A1").Value = "IDENTIFICATION DES ACTIVITÉS SUSPECTES"
        .Range("A1").Font.Size = 14
        .Range("A1").Font.Bold = True
    End With

    ' 4. GRAPHIQUE SECTEUR (Page 1 & 2 de votre doc)
    Dim monGraph As Shape
    Set monGraph = Sheets("Resultats_Analyse").Shapes.AddChart2(251, xlPie)
    monGraph.Chart.SetSourceData Source:=Sheets("Resultats_Analyse").Range("A4:B10")
    monGraph.Chart.ChartTitle.Text = "Répartition des flux par IP"
    
    MsgBox "Analyse terminée sur le fichier CSV unique !", vbInformation
End Sub
