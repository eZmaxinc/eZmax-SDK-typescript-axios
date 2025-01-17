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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatedocumentExtractTextV1ResponseMPayload } from './ezsigntemplatedocument-extract-text-v1-response-mpayload';

/**
 * @type EzsigntemplatedocumentExtractTextV1Response
 * Response for POST /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/extractText
 * @export
 */
/*export type EzsigntemplatedocumentExtractTextV1Response = CommonResponse;*/
export interface EzsigntemplatedocumentExtractTextV1Response {
    /**
     * 
     * @type {EzsigntemplatedocumentExtractTextV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentExtractTextV1Response
     */
    mPayload:EzsigntemplatedocumentExtractTextV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatedocumentExtractTextV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentExtractTextV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatedocumentExtractTextV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentExtractTextV1Response
 */
export class DataObjectEzsigntemplatedocumentExtractTextV1Response {
    mPayload:EzsigntemplatedocumentExtractTextV1ResponseMPayload = new DataObjectEzsigntemplatedocumentExtractTextV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatedocumentExtractTextV1Response Validation Object
 * @class ValidationObjectEzsigntemplatedocumentExtractTextV1Response
 */
export class ValidationObjectEzsigntemplatedocumentExtractTextV1Response {
   mPayload = new ValidationObjectEzsigntemplatedocumentExtractTextV1ResponseMPayload()
} 


