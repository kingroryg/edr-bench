// MITRE ATT&CK Heatmap interactive features
document.addEventListener('DOMContentLoaded', () => {
    const cells = document.querySelectorAll('.heatmap-cell');

    cells.forEach(cell => {
        cell.addEventListener('click', () => {
            const techniqueId = cell.dataset.technique;
            const rate = parseFloat(cell.dataset.rate);

            // Highlight matching rows in the scenario table
            const rows = document.querySelectorAll('table tbody tr');
            rows.forEach(row => {
                const techCell = row.querySelector('td:nth-child(4)');
                if (techCell && techCell.textContent.trim() === techniqueId) {
                    row.style.outline = '2px solid #4361ee';
                    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                } else {
                    row.style.outline = 'none';
                }
            });
        });
    });

    // Sort table by clicking headers
    const table = document.querySelector('.scenarios table');
    if (table) {
        const headers = table.querySelectorAll('th');
        headers.forEach((header, index) => {
            header.style.cursor = 'pointer';
            header.addEventListener('click', () => {
                sortTable(table, index);
            });
        });
    }
});

function sortTable(table, columnIndex) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const isAsc = table.dataset.sortCol === String(columnIndex) && table.dataset.sortDir === 'asc';

    rows.sort((a, b) => {
        const aText = a.cells[columnIndex].textContent.trim();
        const bText = b.cells[columnIndex].textContent.trim();
        const aNum = parseFloat(aText);
        const bNum = parseFloat(bText);

        if (!isNaN(aNum) && !isNaN(bNum)) {
            return isAsc ? bNum - aNum : aNum - bNum;
        }
        return isAsc ? bText.localeCompare(aText) : aText.localeCompare(bText);
    });

    rows.forEach(row => tbody.appendChild(row));
    table.dataset.sortCol = String(columnIndex);
    table.dataset.sortDir = isAsc ? 'desc' : 'asc';
}
