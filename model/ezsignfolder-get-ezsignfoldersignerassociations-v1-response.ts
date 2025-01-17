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
import type { EzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload } from './ezsignfolder-get-ezsignfoldersignerassociations-v1-response-mpayload';

/**
 * @type EzsignfolderGetEzsignfoldersignerassociationsV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolder}/getEzsignfoldersignerassociations
 * @export
 */
/*export type EzsignfolderGetEzsignfoldersignerassociationsV1Response = CommonResponse;*/
export interface EzsignfolderGetEzsignfoldersignerassociationsV1Response {
    /**
     * 
     * @type {EzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload}
     * @memberof EzsignfolderGetEzsignfoldersignerassociationsV1Response
     */
    mPayload:EzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetEzsignfoldersignerassociationsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetEzsignfoldersignerassociationsV1Response
 */
export class DataObjectEzsignfolderGetEzsignfoldersignerassociationsV1Response {
    mPayload:EzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload = new DataObjectEzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetEzsignfoldersignerassociationsV1Response Validation Object
 * @class ValidationObjectEzsignfolderGetEzsignfoldersignerassociationsV1Response
 */
export class ValidationObjectEzsignfolderGetEzsignfoldersignerassociationsV1Response {
   mPayload = new ValidationObjectEzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload()
} 


