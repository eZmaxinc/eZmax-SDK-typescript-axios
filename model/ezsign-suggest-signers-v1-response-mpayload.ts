/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomUserResponse } from './custom-user-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationResponseCompound } from './ezsignfoldersignerassociation-response-compound';

/**
 * Payload for GET /1/module/ezsign/suggestSigners
 * @export
 * @interface EzsignSuggestSignersV1ResponseMPayload
 */
export interface EzsignSuggestSignersV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignfoldersignerassociationResponseCompound>}
     * @memberof EzsignSuggestSignersV1ResponseMPayload
     */
    'a_objEzsignfoldersignerassociation': Array<EzsignfoldersignerassociationResponseCompound>;
    /**
     * 
     * @type {Array<CustomUserResponse>}
     * @memberof EzsignSuggestSignersV1ResponseMPayload
     */
    'a_objUserTeam': Array<CustomUserResponse>;
    /**
     * 
     * @type {Array<CustomUserResponse>}
     * @memberof EzsignSuggestSignersV1ResponseMPayload
     */
    'a_objUser': Array<CustomUserResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignSuggestSignersV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignSuggestSignersV1ResponseMPayload
 */
export class DataObjectEzsignSuggestSignersV1ResponseMPayload {
   a_objEzsignfoldersignerassociation:Array<EzsignfoldersignerassociationResponseCompound> = []
   a_objUserTeam:Array<CustomUserResponse> = []
   a_objUser:Array<CustomUserResponse> = []
}

/**
 * @export 
 * A EzsignSuggestSignersV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignSuggestSignersV1ResponseMPayload
 */
export class ValidationObjectEzsignSuggestSignersV1ResponseMPayload {
   a_objEzsignfoldersignerassociation = {
      type: 'array',
      required: true
   }
   a_objUserTeam = {
      type: 'array',
      required: true
   }
   a_objUser = {
      type: 'array',
      required: true
   }
} 


