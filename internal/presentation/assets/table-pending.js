// Mark the document as pending table enhancement before the body paints, so the
// un-enhanced tables never flash before DataTables renders them.
(function () {
  "use strict";

  var root = document.documentElement;
  root.classList.add("dt-pending");

  // Resource errors do not bubble, so listen during capture before scripts load.
  document.addEventListener("error", function (event) {
    if (event.target && event.target.id === "datatables-init") {
      root.classList.remove("dt-pending");
    }
  }, true);
})();
