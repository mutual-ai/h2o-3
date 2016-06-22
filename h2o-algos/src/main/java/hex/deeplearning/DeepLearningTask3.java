package hex.deeplearning;


import hex.DataInfo;
import hex.FrameTask;
import water.DKV;
import water.H2O;
import water.Key;
import water.gpu.MLPNative;
import water.util.RandomUtils;

import java.util.Arrays;
import java.util.Random;

public class DeepLearningTask3 extends FrameTask<DeepLearningTask3> {

  static {
    System.loadLibrary("mlp");
  }

  final private boolean _training;
  private DeepLearningModelInfo _sharedmodel; //input/output
  private DeepLearningModelInfo _localmodel;
  transient Random _dropout_rng;
  transient MLPNative _mlp;
  private float[] aptr_x;
  private float[] aptr_y;

  public DeepLearningTask3(Key jobKey, DeepLearningModelInfo inputModel, float fraction, int iteration) {
    this(jobKey, inputModel, fraction, iteration, null);
  }

  public DeepLearningTask3(Key jobKey, DeepLearningModelInfo inputModel, float fraction, int iteration, H2O.H2OCountedCompleter cmp) {
    super(jobKey, inputModel.data_info(), inputModel.get_params()._seed + inputModel.get_processed_global(), iteration, inputModel.get_params()._sparse, cmp);
    assert (inputModel.get_processed_local() == 0);
    _training = true;
    _sharedmodel = inputModel;
    _useFraction = fraction;
    _shuffle = model_info().get_params()._shuffle_training_data;
  }

  final public DeepLearningModelInfo model_info() {
    assert (_sharedmodel != null);
    return _sharedmodel;
  }

  @Override
  protected void setupLocal() {
    assert (_localmodel == null);
    super.setupLocal();
    if (model_info().get_params()._elastic_averaging) {
      //Load my local model from DKV, to continue training
      _localmodel = DKV.getGet(_sharedmodel.localModelInfoKey(H2O.SELF));
      if (_localmodel != null) {
        if (!Arrays.equals(_localmodel.units, _sharedmodel.units)) {
          _localmodel = _sharedmodel.deep_clone();
        } else {
          //Make sure that the local model has the right global (shared) parameters after checkpoint restart!
          _localmodel.set_params(_sharedmodel.get_params(), _sharedmodel._model_id);
          _localmodel.set_processed_global(_sharedmodel.get_processed_global());
        }
      } else {
        // first time around - use the randomized initial weights and don't spread the shared (random) model
        _localmodel = _sharedmodel.deep_clone();
        _sharedmodel = null;
      }
    } else {
      _localmodel = _sharedmodel;
      _sharedmodel = null;
    }
    _localmodel.set_processed_local(0);
  }

  private static MLPNative makeMLPNative(final DeepLearningModelInfo minfo) {
    MLPNative m = new MLPNative();

    return m;
  }


  @Override
  protected boolean chunkInit() {

    if (_localmodel.get_processed_local() >= _useFraction * _fr.numRows())
      return false;
    _mlp = makeMLPNative(_localmodel);
    _dropout_rng = RandomUtils.getRNG(System.currentTimeMillis());
    return true;
  }

  @Override public final void processRow(long seed, DataInfo.Row r, int mb) {
    if (_localmodel.get_params()._reproducible) {
      seed += _localmodel.get_processed_global(); //avoid periodicity
    } else {
      seed = _dropout_rng.nextLong(); // non-reproducible case - make a fast & good random number
    }
    _localmodel.checkMissingCats(r.binIds);
  }

  @Override
  protected void processRow(long gid, DataInfo.Row[] rows, int mb) {


  }
}
