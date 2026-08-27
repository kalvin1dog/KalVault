window.generateVaultPdfFromBlazor = function (fileName, entriesList) {

    // Get jsPDF from the UMD browser export
    const jspdfModule = window.jspdf || window.jsPDF;

    if (!jspdfModule) {
        alert("The PDF generator library is not loaded. Please check that jsPDF has loaded.");
        console.error("jsPDF is not available. window.jspdf =", window.jspdf);
        console.error("window.jsPDF =", window.jsPDF);
        return;
    }

    const jsPDF = jspdfModule.jsPDF || jspdfModule;

    if (typeof jsPDF !== "function") {
        alert("jsPDF was found, but the constructor is unavailable.");
        console.error("Invalid jsPDF object:", jspdfModule);
        return;
    }

    // Check AutoTable
    if (typeof window.jspdf === "undefined" ||
        typeof window.jspdf.jsPDF === "undefined") {
        console.warn("jsPDF module detected.");
    }

    try {

        const doc = new jsPDF('l', 'mm', 'a4');

        doc.setFont('Helvetica', 'bold');
        doc.setFontSize(18);
        doc.text(
            'KalPass Vault - Full Account Credentials Report',
            14,
            15
        );

        doc.setFont('Helvetica', 'normal');
        doc.setFontSize(10);
        doc.setTextColor(100);

        doc.text(
            'Generated on: ' + new Date().toLocaleString(),
            14,
            22
        );

        doc.setFont('Helvetica', 'bold');
        doc.setTextColor(200, 50, 50);

        doc.text(
            '! WARNING: This document contains unencrypted passwords. Keep this file physically secure or destroy it after use.',
            14,
            28
        );

        const tableHeaders = [
            ['Title', 'URL / Link', 'Username', 'Password', 'Notes']
        ];

        // Blazor serializes C# properties as camelCase
        const tableData = (entriesList || []).map(item => [
            item.title || '',
            item.url || '',
            item.username || '',
            item.password || '',
            item.notes || ''
        ]);

        // Check that AutoTable is available
        if (typeof doc.autoTable !== 'function') {
            alert(
                'The PDF table plugin is not loaded. Please check that jspdf-autotable is loaded.'
            );

            console.error(
                'doc.autoTable is not available.'
            );

            return;
        }

        doc.autoTable({
            head: tableHeaders,
            body: tableData,

            startY: 33,

            theme: 'striped',

            headStyles: {
                fillColor: [44, 62, 80],
                fontSize: 10,
                fontStyle: 'bold'
            },

            bodyStyles: {
                fontSize: 9,
                valign: 'top'
            },

            columnStyles: {
                0: {
                    cellWidth: 40
                },

                1: {
                    cellWidth: 50
                },

                2: {
                    cellWidth: 45
                },

                3: {
                    cellWidth: 45,
                    font: 'Courier'
                },

                4: {
                    cellWidth: 'auto'
                }
            },

            styles: {
                overflow: 'linebreak'
            },

            didDrawPage: function () {

                doc.setFontSize(8);
                doc.setTextColor(150);

                doc.text(
                    'Page ' +
                    doc.internal.getNumberOfPages(),

                    doc.internal.pageSize.width - 20,

                    doc.internal.pageSize.height - 10
                );
            }
        });

        doc.save(fileName);

        console.log(
            'PDF successfully generated:',
            fileName
        );

    }
    catch (error) {

        console.error(
            'Error generating PDF:',
            error
        );

        alert(
            'Unable to generate the PDF: ' +
            error.message
        );
    }
};

