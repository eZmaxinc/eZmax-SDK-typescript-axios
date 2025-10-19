# EzsigntemplatepackagemembershipResponseCompound

A Ezsigntemplatepackagemembership Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatepackagemembershipID** | **number** | The unique ID of the Ezsigntemplatepackagemembership | [default to undefined]
**fkiEzsigntemplatepackageID** | **number** | The unique ID of the Ezsigntemplatepackage | [default to undefined]
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**iEzsigntemplatepackagemembershipOrder** | **number** | The order in which the Ezsigntemplate will be imported when using an Ezsigntemplatepackage. | [default to undefined]
**objEzsigntemplate** | [**EzsigntemplateResponseCompound**](EzsigntemplateResponseCompound.md) |  | [default to undefined]
**a_objEzsigntemplatepackagesignermembership** | [**Array&lt;EzsigntemplatepackagesignermembershipResponseCompound&gt;**](EzsigntemplatepackagesignermembershipResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { EzsigntemplatepackagemembershipResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatepackagemembershipResponseCompound = {
    pkiEzsigntemplatepackagemembershipID,
    fkiEzsigntemplatepackageID,
    fkiEzsigntemplateID,
    iEzsigntemplatepackagemembershipOrder,
    objEzsigntemplate,
    a_objEzsigntemplatepackagesignermembership,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
