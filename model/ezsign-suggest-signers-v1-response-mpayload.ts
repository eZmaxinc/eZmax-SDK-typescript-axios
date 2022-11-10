/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
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

import { DefaultObject } from '../base'

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
 * A EzsignSuggestSignersV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignSuggestSignersV1ResponseMPayload
 */
export class DefaultObjectEzsignSuggestSignersV1ResponseMPayload extends DefaultObject {
   a_objEzsignfoldersignerassociation:Array<EzsignfoldersignerassociationResponseCompound> = []
   a_objUserTeam:Array<CustomUserResponse> = []
   a_objUser:Array<CustomUserResponse> = []
}


