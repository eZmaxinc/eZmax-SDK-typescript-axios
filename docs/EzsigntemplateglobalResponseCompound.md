# EzsigntemplateglobalResponseCompound

A Ezsigntemplateglobal Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplateglobalID** | **number** | The unique ID of the Ezsigntemplateglobal | [default to undefined]
**fkiEzsigntemplateglobaldocumentID** | **number** | The unique ID of the Ezsigntemplateglobaldocument | [default to undefined]
**fkiModuleID** | **number** | The unique ID of the Module | [default to undefined]
**sModuleNameX** | **string** | The Name of the Module in the language of the requester | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sLanguageNameX** | **string** | The Name of the Language in the language of the requester | [default to undefined]
**eEzsigntemplateglobalModule** | [**FieldEEzsigntemplateglobalModule**](FieldEEzsigntemplateglobalModule.md) |  | [default to undefined]
**eEzsigntemplateglobalSupplier** | [**FieldEEzsigntemplateglobalSupplier**](FieldEEzsigntemplateglobalSupplier.md) |  | [default to undefined]
**sEzsigntemplateglobalCode** | **string** | The Code of the Ezsigntemplateglobal | [default to undefined]
**sEzsigntemplateglobalDescription** | **string** | The description of the Ezsigntemplate | [default to undefined]
**objEzsigntemplateglobaldocument** | [**EzsigntemplateglobaldocumentResponse**](EzsigntemplateglobaldocumentResponse.md) |  | [optional] [default to undefined]
**a_objEzsigntemplateglobalsigner** | [**Array&lt;EzsigntemplateglobalsignerResponseCompound&gt;**](EzsigntemplateglobalsignerResponseCompound.md) |  | [default to undefined]
**a_objEzsigntemplateglobalannotation** | [**Array&lt;EzsigntemplateglobalannotationResponseCompound&gt;**](EzsigntemplateglobalannotationResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsigntemplateglobalResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplateglobalResponseCompound = {
    pkiEzsigntemplateglobalID,
    fkiEzsigntemplateglobaldocumentID,
    fkiModuleID,
    sModuleNameX,
    fkiLanguageID,
    sLanguageNameX,
    eEzsigntemplateglobalModule,
    eEzsigntemplateglobalSupplier,
    sEzsigntemplateglobalCode,
    sEzsigntemplateglobalDescription,
    objEzsigntemplateglobaldocument,
    a_objEzsigntemplateglobalsigner,
    a_objEzsigntemplateglobalannotation,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
