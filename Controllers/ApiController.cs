using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
namespace WebSocketServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ApiController : ControllerBase
    {
        IHubContext<MyHub> _hubContext;
       

        public ApiController(IHubContext<MyHub> hubContext)
        {
            _hubContext = hubContext;
        }

    }
}