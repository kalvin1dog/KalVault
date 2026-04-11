window.downloadFile = (fileName, base64Data) => {
        const link = document.createElement('a');
        link.download = fileName;
    //link.href = "data:text/csv;base64," + base64Data;
    link.href = "data:text/csv;charset=utf-8," + base64Data;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
};


