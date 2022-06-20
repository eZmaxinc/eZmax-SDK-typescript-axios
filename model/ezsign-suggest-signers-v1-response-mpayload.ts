/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CustomUserResponse } from './custom-user-response';
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
