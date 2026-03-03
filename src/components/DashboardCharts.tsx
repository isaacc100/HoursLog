'use client'

import { useEffect, useRef } from 'react'
import { Chart, registerables } from 'chart.js'

Chart.register(...registerables)

interface ChartData {
  name: string
  hours: number
  color?: string
}

export default function DashboardCharts({ type, data }: { type: 'doughnut' | 'bar'; data: ChartData[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const chartRef = useRef<Chart | null>(null)
  
  useEffect(() => {
    if (!canvasRef.current || data.length === 0) return
    
    if (chartRef.current) chartRef.current.destroy()
    
    const labels = data.map(d => d.name)
    const values = data.map(d => d.hours)
    const colors = data.map((d, i) => d.color || [
      '#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8',
      '#6610f2', '#e83e8c', '#fd7e14', '#20c997', '#6f42c1',
    ][i % 10])
    
    chartRef.current = new Chart(canvasRef.current, {
      type: type === 'doughnut' ? 'doughnut' : 'bar',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderWidth: type === 'doughnut' ? 2 : 0,
          borderColor: type === 'doughnut' ? '#fff' : undefined,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        indexAxis: type === 'bar' ? 'y' : undefined,
        plugins: {
          legend: { display: type === 'doughnut', position: 'bottom' },
        },
        scales: type === 'bar' ? {
          x: { beginAtZero: true, title: { display: true, text: 'Hours' } },
        } : undefined,
      },
    })
    
    return () => { chartRef.current?.destroy() }
  }, [data, type])
  
  if (data.length === 0) return <p className="text-muted text-center">No data available</p>
  
  return <canvas ref={canvasRef}></canvas>
}
