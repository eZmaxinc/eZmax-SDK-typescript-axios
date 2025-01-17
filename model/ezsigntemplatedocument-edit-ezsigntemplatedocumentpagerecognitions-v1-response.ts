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
import type { EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload } from './ezsigntemplatedocument-edit-ezsigntemplatedocumentpagerecognitions-v1-response-mpayload';

/**
 * @type EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response
 * Response for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplatedocumentpagerecognitions
 * @export
 */
/*export type EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response = CommonResponse;*/
export interface EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response {
    /**
     * 
     * @type {EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response
     */
    mPayload:EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response
 */
export class DataObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response {
    mPayload:EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload = new DataObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response
 */
export class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response {
   mPayload = new ValidationObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload()
} 


