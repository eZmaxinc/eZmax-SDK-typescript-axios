# CommonReportgroup

A group of reports  Each Reportgroup is for a specific recipient or for a specific context.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_objReport** | [**Array&lt;CommonReport&gt;**](CommonReport.md) |  | [default to undefined]
**a_objReportcellstyleCustom** | [**Array&lt;CommonReportcellstyle&gt;**](CommonReportcellstyle.md) |  | [default to undefined]
**a_objReportgroupParameter** | [**Array&lt;CommonReportgroupParameter&gt;**](CommonReportgroupParameter.md) |  | [default to undefined]
**sReportgroupFilename** | **string** | The name of the file | [default to undefined]

## Example

```typescript
import { CommonReportgroup } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonReportgroup = {
    a_objReport,
    a_objReportcellstyleCustom,
    a_objReportgroupParameter,
    sReportgroupFilename,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
