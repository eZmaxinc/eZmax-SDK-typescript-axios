# ObjectClonehistoryApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**clonehistoryGetListV1**](#clonehistorygetlistv1) | **GET** /1/object/clonehistory/getList | Retrieve Clonehistory list|

# **clonehistoryGetListV1**
> ClonehistoryGetListV1Response clonehistoryGetListV1()



### Example

```typescript
import {
    ObjectClonehistoryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectClonehistoryApi(configuration);

let eOrderBy: 'pkiClonehistoryID_ASC' | 'pkiClonehistoryID_DESC' | 'fkiUserIDCloning_ASC' | 'fkiUserIDCloning_DESC' | 'fkiUserIDCloned_ASC' | 'fkiUserIDCloned_DESC' | 'dtClonehistoryFirsthit_ASC' | 'dtClonehistoryFirsthit_DESC' | 'dtClonehistoryLasthit_ASC' | 'dtClonehistoryLasthit_DESC' | 'sUserLoginnameCloning_ASC' | 'sUserLoginnameCloning_DESC' | 'sUserFirstnameCloning_ASC' | 'sUserFirstnameCloning_DESC' | 'sUserLastnameCloning_ASC' | 'sUserLastnameCloning_DESC' | 'sUserLoginnameCloned_ASC' | 'sUserLoginnameCloned_DESC' | 'sUserFirstnameCloned_ASC' | 'sUserFirstnameCloned_DESC' | 'sUserLastnameCloned_ASC' | 'sUserLastnameCloned_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.clonehistoryGetListV1(
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
| **eOrderBy** | [**&#39;pkiClonehistoryID_ASC&#39; | &#39;pkiClonehistoryID_DESC&#39; | &#39;fkiUserIDCloning_ASC&#39; | &#39;fkiUserIDCloning_DESC&#39; | &#39;fkiUserIDCloned_ASC&#39; | &#39;fkiUserIDCloned_DESC&#39; | &#39;dtClonehistoryFirsthit_ASC&#39; | &#39;dtClonehistoryFirsthit_DESC&#39; | &#39;dtClonehistoryLasthit_ASC&#39; | &#39;dtClonehistoryLasthit_DESC&#39; | &#39;sUserLoginnameCloning_ASC&#39; | &#39;sUserLoginnameCloning_DESC&#39; | &#39;sUserFirstnameCloning_ASC&#39; | &#39;sUserFirstnameCloning_DESC&#39; | &#39;sUserLastnameCloning_ASC&#39; | &#39;sUserLastnameCloning_DESC&#39; | &#39;sUserLoginnameCloned_ASC&#39; | &#39;sUserLoginnameCloned_DESC&#39; | &#39;sUserFirstnameCloned_ASC&#39; | &#39;sUserFirstnameCloned_DESC&#39; | &#39;sUserLastnameCloned_ASC&#39; | &#39;sUserLastnameCloned_DESC&#39;**]**Array<&#39;pkiClonehistoryID_ASC&#39; &#124; &#39;pkiClonehistoryID_DESC&#39; &#124; &#39;fkiUserIDCloning_ASC&#39; &#124; &#39;fkiUserIDCloning_DESC&#39; &#124; &#39;fkiUserIDCloned_ASC&#39; &#124; &#39;fkiUserIDCloned_DESC&#39; &#124; &#39;dtClonehistoryFirsthit_ASC&#39; &#124; &#39;dtClonehistoryFirsthit_DESC&#39; &#124; &#39;dtClonehistoryLasthit_ASC&#39; &#124; &#39;dtClonehistoryLasthit_DESC&#39; &#124; &#39;sUserLoginnameCloning_ASC&#39; &#124; &#39;sUserLoginnameCloning_DESC&#39; &#124; &#39;sUserFirstnameCloning_ASC&#39; &#124; &#39;sUserFirstnameCloning_DESC&#39; &#124; &#39;sUserLastnameCloning_ASC&#39; &#124; &#39;sUserLastnameCloning_DESC&#39; &#124; &#39;sUserLoginnameCloned_ASC&#39; &#124; &#39;sUserLoginnameCloned_DESC&#39; &#124; &#39;sUserFirstnameCloned_ASC&#39; &#124; &#39;sUserFirstnameCloned_DESC&#39; &#124; &#39;sUserLastnameCloned_ASC&#39; &#124; &#39;sUserLastnameCloned_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**ClonehistoryGetListV1Response**

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

