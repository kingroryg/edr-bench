// MITRE ATT&CK Heatmap interactive features + step detail toggles
document.addEventListener('DOMContentLoaded', () => {
    // Heatmap cell click: highlight matching scenario rows
    const cells = document.querySelectorAll('.heatmap-cell');
    cells.forEach(cell => {
        cell.addEventListener('click', () => {
            const techniqueId = cell.dataset.technique;
            const rows = document.querySelectorAll('table tbody tr.scenario-row');
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

    // Step detail expand/collapse
    document.querySelectorAll('.expand-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const row = btn.closest('tr');
            const detailRow = row.nextElementSibling;
            if (!detailRow || !detailRow.classList.contains('step-detail-row')) return;

            const isOpen = detailRow.classList.contains('open');
            detailRow.classList.toggle('open');
            btn.setAttribute('aria-expanded', !isOpen);
        });
    });

    // Sort table by clicking headers (skip step-detail-rows)
    const table = document.querySelector('.scenarios table');
    if (table) {
        const headers = table.querySelectorAll('th');
        headers.forEach((header, index) => {
            header.style.cursor = 'pointer';
            header.addEventListener('click', () => sortTable(table, index));
        });
    }
});

function sortTable(table, columnIndex) {
    const tbody = table.querySelector('tbody');
    // Collect scenario row pairs: [scenarioRow, stepDetailRow]
    const pairs = [];
    const rows = Array.from(tbody.children);
    for (let i = 0; i < rows.length; i++) {
        if (rows[i].classList.contains('scenario-row')) {
            const detail = (i + 1 < rows.length && rows[i + 1].classList.contains('step-detail-row'))
                ? rows[i + 1] : null;
            pairs.push({ main: rows[i], detail: detail });
            if (detail) i++; // skip the detail row
        }
    }

    const isAsc = table.dataset.sortCol === String(columnIndex) && table.dataset.sortDir === 'asc';

    pairs.sort((a, b) => {
        const aText = a.main.cells[columnIndex]?.textContent.trim() || '';
        const bText = b.main.cells[columnIndex]?.textContent.trim() || '';
        const aNum = parseFloat(aText);
        const bNum = parseFloat(bText);

        if (!isNaN(aNum) && !isNaN(bNum)) {
            return isAsc ? bNum - aNum : aNum - bNum;
        }
        return isAsc ? bText.localeCompare(aText) : aText.localeCompare(bText);
    });

    pairs.forEach(pair => {
        tbody.appendChild(pair.main);
        if (pair.detail) tbody.appendChild(pair.detail);
    });

    table.dataset.sortCol = String(columnIndex);
    table.dataset.sortDir = isAsc ? 'desc' : 'asc';
}
