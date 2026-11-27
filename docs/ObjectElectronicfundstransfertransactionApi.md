# ObjectElectronicfundstransfertransactionApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**electronicfundstransfertransactionGetListV1**](#electronicfundstransfertransactiongetlistv1) | **GET** /1/object/electronicfundstransfertransaction/getList | Retrieve Electronicfundstransfertransaction list|

# **electronicfundstransfertransactionGetListV1**
> ElectronicfundstransfertransactionGetListV1Response electronicfundstransfertransactionGetListV1()



### Example

```typescript
import {
    ObjectElectronicfundstransfertransactionApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransfertransactionApi(configuration);

let eOrderBy: 'pkiElectronicfundstransfertransactionID_ASC' | 'pkiElectronicfundstransfertransactionID_DESC' | 'dElectronicfundstransfertransactionAmount_ASC' | 'dElectronicfundstransfertransactionAmount_DESC' | 'dtElectronicfundstransfertransactionDate_ASC' | 'dtElectronicfundstransfertransactionDate_DESC' | 'iElectronicfundstransferNumber_ASC' | 'iElectronicfundstransferNumber_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.electronicfundstransfertransactionGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiElectronicfundstransfertransactionID_ASC&#39; | &#39;pkiElectronicfundstransfertransactionID_DESC&#39; | &#39;dElectronicfundstransfertransactionAmount_ASC&#39; | &#39;dElectronicfundstransfertransactionAmount_DESC&#39; | &#39;dtElectronicfundstransfertransactionDate_ASC&#39; | &#39;dtElectronicfundstransfertransactionDate_DESC&#39; | &#39;iElectronicfundstransferNumber_ASC&#39; | &#39;iElectronicfundstransferNumber_DESC&#39;**]**Array<&#39;pkiElectronicfundstransfertransactionID_ASC&#39; &#124; &#39;pkiElectronicfundstransfertransactionID_DESC&#39; &#124; &#39;dElectronicfundstransfertransactionAmount_ASC&#39; &#124; &#39;dElectronicfundstransfertransactionAmount_DESC&#39; &#124; &#39;dtElectronicfundstransfertransactionDate_ASC&#39; &#124; &#39;dtElectronicfundstransfertransactionDate_DESC&#39; &#124; &#39;iElectronicfundstransferNumber_ASC&#39; &#124; &#39;iElectronicfundstransferNumber_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**ElectronicfundstransfertransactionGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

