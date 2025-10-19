# EzsigntemplateformfieldResponseCompound

An Ezsigntemplateformfield Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplateformfieldID** | **number** | The unique ID of the Ezsigntemplateformfield | [default to undefined]
**eEzsigntemplateformfieldPositioning** | [**FieldEEzsigntemplateformfieldPositioning**](FieldEEzsigntemplateformfieldPositioning.md) |  | [optional] [default to undefined]
**iEzsigntemplatedocumentpagePagenumber** | **number** | The page number in the Ezsigntemplatedocument | [default to undefined]
**sEzsigntemplateformfieldLabel** | **string** | The Label for the Ezsigntemplateformfield | [default to undefined]
**sEzsigntemplateformfieldValue** | **string** | The value for the Ezsigntemplateformfield | [optional] [default to undefined]
**iEzsigntemplateformfieldX** | **number** | The X coordinate (Horizontal) where to put the Ezsigntemplateformfield on the Ezsigntemplatepage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplateformfield 2 inches from the left border of the page, you would use \&quot;200\&quot; for the X coordinate. | [optional] [default to undefined]
**iEzsigntemplateformfieldY** | **number** | The Y coordinate (Vertical) where to put the Ezsigntemplateformfield on the Ezsigntemplatepage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplateformfield 3 inches from the top border of the page, you would use \&quot;300\&quot; for the Y coordinate. | [optional] [default to undefined]
**iEzsigntemplateformfieldWidth** | **number** | The Width of the Ezsigntemplateformfield in pixels calculated at 100 DPI | [default to undefined]
**iEzsigntemplateformfieldHeight** | **number** | The Height of the Ezsigntemplateformfield in pixels calculated at 100 DPI  | [default to undefined]
**bEzsigntemplateformfieldAutocomplete** | **boolean** | Whether the Ezsigntemplateformfield allows the use of the autocomplete of the browser.  This can only be set if eEzsigntemplateformfieldgroupType is **Text** | [optional] [default to undefined]
**bEzsigntemplateformfieldSelected** | **boolean** | Whether the Ezsigntemplateformfield is selected or not by default.  This can only be set if eEzsigntemplateformfieldgroupType is **Checkbox** or **Radio** | [optional] [default to undefined]
**eEzsigntemplateformfieldDependencyrequirement** | [**FieldEEzsigntemplateformfieldDependencyrequirement**](FieldEEzsigntemplateformfieldDependencyrequirement.md) |  | [optional] [default to undefined]
**sEzsigntemplateformfieldPositioningpattern** | **string** | The string pattern to search for the positioning. **This is not a regexp**  This will be required if **eEzsigntemplateformfieldPositioning** is set to **PerCoordinates** | [optional] [default to undefined]
**iEzsigntemplateformfieldPositioningoffsetx** | **number** | The offset X  This will be required if **eEzsigntemplateformfieldPositioning** is set to **PerCoordinates** | [optional] [default to undefined]
**iEzsigntemplateformfieldPositioningoffsety** | **number** | The offset Y  This will be required if **eEzsigntemplateformfieldPositioning** is set to **PerCoordinates** | [optional] [default to undefined]
**eEzsigntemplateformfieldPositioningoccurence** | [**FieldEEzsigntemplateformfieldPositioningoccurence**](FieldEEzsigntemplateformfieldPositioningoccurence.md) |  | [optional] [default to undefined]
**eEzsigntemplateformfieldHorizontalalignment** | [**EnumHorizontalalignment**](EnumHorizontalalignment.md) |  | [optional] [default to undefined]
**objTextstylestatic** | [**TextstylestaticResponseCompound**](TextstylestaticResponseCompound.md) |  | [optional] [default to undefined]
**a_objEzsigntemplateelementdependency** | [**Array&lt;EzsigntemplateelementdependencyResponseCompound&gt;**](EzsigntemplateelementdependencyResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsigntemplateformfieldResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplateformfieldResponseCompound = {
    pkiEzsigntemplateformfieldID,
    eEzsigntemplateformfieldPositioning,
    iEzsigntemplatedocumentpagePagenumber,
    sEzsigntemplateformfieldLabel,
    sEzsigntemplateformfieldValue,
    iEzsigntemplateformfieldX,
    iEzsigntemplateformfieldY,
    iEzsigntemplateformfieldWidth,
    iEzsigntemplateformfieldHeight,
    bEzsigntemplateformfieldAutocomplete,
    bEzsigntemplateformfieldSelected,
    eEzsigntemplateformfieldDependencyrequirement,
    sEzsigntemplateformfieldPositioningpattern,
    iEzsigntemplateformfieldPositioningoffsetx,
    iEzsigntemplateformfieldPositioningoffsety,
    eEzsigntemplateformfieldPositioningoccurence,
    eEzsigntemplateformfieldHorizontalalignment,
    objTextstylestatic,
    a_objEzsigntemplateelementdependency,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
