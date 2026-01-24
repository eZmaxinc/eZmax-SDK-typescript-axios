# CommonReportrow

A row in a Reportsubsectionpart 

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_objReportcell** | [**Array&lt;CommonReportcell&gt;**](CommonReportcell.md) |  | [default to undefined]
**objVariableobject** | **{ [key: string]: any; }** | A Variable object without predefined property names | [default to undefined]
**iReportrowHeight** | **number** | The reportrow height in pixels | [default to undefined]
**objReportcellstyleCustom** | [**CommonReportcellstylecustom**](CommonReportcellstylecustom.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CommonReportrow } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonReportrow = {
    a_objReportcell,
    objVariableobject,
    iReportrowHeight,
    objReportcellstyleCustom,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
