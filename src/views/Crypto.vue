<style scoped>
.addmargin {
  margin-top: 10px;
  margin-bottom: 10px;
}

.vue-logo-back {
  background-color: black;
}

.logo {
  width: 144px;
}

.fullbody {
  width: 100%;
}

</style>
<template>
  <div class="home">
    <div class="col-md-8 centeralign">
      <b-card no-body style="padding: 20px">
        <b-tabs content-class="mt-3">
        
          <b-tab title="Symmetric">
            <Symmetric />
          </b-tab>
          <b-tab title="Asymmetric">
            <Asymmetric />
          </b-tab>
         
        </b-tabs>
      </b-card>
    </div>
  </div>
</template>

<script>

import Asymmetric from "@/components/Asymmetric.vue";
import Symmetric from "@/components/Symmetric.vue";


export default {
  name: "PanelPage",
  components: {
   
    Asymmetric,
    Symmetric,
  
  },
  data() {
    return {
      active: 0
    };
  },
  created() {},
  methods: {
    gotosubpage: id => {
      this.$router.push(`${id}`);
    }
  }
};
</script>
