/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { EzdoctemplatedocumentGetListV1ResponseMPayload } from './ezdoctemplatedocument-get-list-v1-response-mpayload';

/**
 * @type EzdoctemplatedocumentGetListV1Response
 * Response for GET /1/object/ezdoctemplatedocument/getList
 * @export
 */
/*export type EzdoctemplatedocumentGetListV1Response = CommonResponseGetList;*/
export interface EzdoctemplatedocumentGetListV1Response {
    /**
     * 
     * @type {EzdoctemplatedocumentGetListV1ResponseMPayload}
     * @memberof EzdoctemplatedocumentGetListV1Response
     */
    mPayload:EzdoctemplatedocumentGetListV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzdoctemplatedocumentGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzdoctemplatedocumentGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A EzdoctemplatedocumentGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzdoctemplatedocumentGetListV1Response
 */
export class DataObjectEzdoctemplatedocumentGetListV1Response {
    mPayload:EzdoctemplatedocumentGetListV1ResponseMPayload = new DataObjectEzdoctemplatedocumentGetListV1ResponseMPayload()
}

/**
 * @export 
 * A EzdoctemplatedocumentGetListV1Response Validation Object
 * @class ValidationObjectEzdoctemplatedocumentGetListV1Response
 */
export class ValidationObjectEzdoctemplatedocumentGetListV1Response {
   mPayload = new ValidationObjectEzdoctemplatedocumentGetListV1ResponseMPayload()
} 


