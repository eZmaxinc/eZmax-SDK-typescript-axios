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
import type { EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload } from './ezsignfolder-import-ezsigntemplatepackage-v1-response-mpayload';

/**
 * @type EzsignfolderImportEzsigntemplatepackageV1Response
 * Response for POST/1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage
 * @export
 */
/*export type EzsignfolderImportEzsigntemplatepackageV1Response = CommonResponse;*/
export interface EzsignfolderImportEzsigntemplatepackageV1Response {
    /**
     * 
     * @type {EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload}
     * @memberof EzsignfolderImportEzsigntemplatepackageV1Response
     */
    mPayload:EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderImportEzsigntemplatepackageV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderImportEzsigntemplatepackageV1Response
 */
export class DataObjectEzsignfolderImportEzsigntemplatepackageV1Response {
    mPayload:EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload = new DataObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderImportEzsigntemplatepackageV1Response Validation Object
 * @class ValidationObjectEzsignfolderImportEzsigntemplatepackageV1Response
 */
export class ValidationObjectEzsignfolderImportEzsigntemplatepackageV1Response {
   mPayload = new ValidationObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload()
} 


