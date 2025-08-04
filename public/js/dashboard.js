document.addEventListener('DOMContentLoaded', async function () {
  try {
    // Define a custom color scale with #072589 as the primary color
    const customColorsPie = d3.scaleOrdinal()
      .range(['#072589', '#F467C0', '#33FF57', '#3357FF', '#F1C40F']);
    const customColorsBar = d3.scaleOrdinal()
      .range(['#072589']);

    // Fetch the validation data
    const response = await fetch('/dashboard-data');
    const rawData = await response.json();

    // Crossfilter initialization
    const ndx = crossfilter(rawData);

    const formatDateToMonth = date => {
      const d = new Date(date);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    };

    // Dimensions
    const monthDimension = ndx.dimension(d => formatDateToMonth(d.createdAt));
    const schemaDimension = ndx.dimension(d => d.validation.schemaPresent ? 'With Schema' : 'Without Schema');
    const validDimension = ndx.dimension(d => d.validation.valid ? 'Valid' : 'Invalid');
    const typeDimension = ndx.dimension(d => d.validation.type);

    // Groups
    const validationsByMonthGroup = monthDimension.group();
    const schemaUsage = schemaDimension.group();
    const validationState = validDimension.group();
    const typeGroup = typeDimension.group();

    // Special handling for error types
    const errorTypeToRecordsMap = {};

    const errorTypeDimension = ndx.dimension(d => {
      const errors = d.validation.errors || [];
      if (errors.length > 0) {
        errors.forEach(error => {
          if (!errorTypeToRecordsMap[error.type]) {
            errorTypeToRecordsMap[error.type] = [];
          }
          errorTypeToRecordsMap[error.type].push(d);
        });
        return errors.map(error => error.type);
      } else {
        if (!errorTypeToRecordsMap["No Errors"]) {
          errorTypeToRecordsMap["No Errors"] = [];
        }
        errorTypeToRecordsMap["No Errors"].push(d);
        return ["No Errors"];
      }
    });

    const errorTypeGroup = {
      all: () => {
        const flattenedErrors = {};
        errorTypeDimension.top(Infinity).forEach(record => {
          const errors = record.validation.errors || [];
          if (errors.length > 0) {
            errors.forEach(error => {
              flattenedErrors[error.type] = (flattenedErrors[error.type] || 0) + 1;
            });
          } else {
            flattenedErrors["No Errors"] = (flattenedErrors["No Errors"] || 0) + 1;
          }
        });
        return Object.entries(flattenedErrors).map(([key, value]) => ({ key, value }));
      },
    };

    // Charts
    const validationsByMonthChart = dc.barChart('#validations-by-month-chart');
    const validationTypeChart = dc.pieChart('#validation-type-chart');
    const schemaUsageChart = dc.pieChart('#schema-usage-chart');
    const validationStateChart = dc.pieChart('#validation-state-chart');
    const errorTypesChart = dc.rowChart('#error-types-chart');

    // Total Validations Counter
    const all = ndx.groupAll();
    const updateTotalCount = () => {
      document.getElementById('validation-count').textContent = all.value();
    };

    // Validations by Month Chart
    validationsByMonthChart
      .width(600)
      .height(300)
      .dimension(monthDimension)
      .group(validationsByMonthGroup)
      .x(d3.scaleBand().domain(validationsByMonthGroup.all().map(d => d.key)))
      .xUnits(dc.units.ordinal)
      .colors(customColorsBar)
      .colorAccessor((d, i) => i) // Ensures it starts from the first color
      .elasticY(true)
      .renderHorizontalGridLines(true)
      .xAxisLabel('Month')
      .yAxisLabel('Number of Validations')
      .on('renderlet', function(chart) {
        chart.selectAll('g.x text').style('text-anchor', 'end').attr('transform', 'rotate(-45)');
      });

    // Validation Type Chart
    validationTypeChart
      .width(300)
      .height(300)
      .dimension(typeDimension)
      .group(typeGroup)
      .colors(customColorsPie)
      .colorAccessor((d, i) => i)
      .label(d => d.key)
      .title(d => `${d.key}: ${d.value}`);

    // Schema Usage Chart
    schemaUsageChart
      .width(300)
      .height(300)
      .dimension(schemaDimension)
      .group(schemaUsage)
      .colors(customColorsPie)
      .colorAccessor((d, i) => i)
      .label(d => d.key)
      .title(d => `${d.key}: ${d.value}`);

    // Validation State Chart
    validationStateChart
      .width(300)
      .height(300)
      .dimension(validDimension)
      .group(validationState)
      .colors(customColorsPie)
      .colorAccessor((d, i) => i)
      .label(d => d.key)
      .title(d => `${d.key}: ${d.value}`);

    // Error Types Chart
    errorTypesChart
      .width(600)
      .height(400)
      .dimension(errorTypeDimension)
      .group(errorTypeGroup)
      .colors(customColorsBar)
      .colorAccessor((d, i) => i)
      .label(d => d.key)
      .title(d => `${d.key}: ${d.value}`)
      .elasticX(true)
      .xAxis().ticks(5);

    // Render all charts
    dc.renderAll();

    // Update total count
    updateTotalCount();

    // Add event listener for count updates
    dc.events.on('filtered', updateTotalCount);

  } catch (error) {
    console.error('Error loading dashboard data:', error);
    document.getElementById('dashboard-content').innerHTML = '<p>Error loading dashboard data. Please try again later.</p>';
  }
}); 