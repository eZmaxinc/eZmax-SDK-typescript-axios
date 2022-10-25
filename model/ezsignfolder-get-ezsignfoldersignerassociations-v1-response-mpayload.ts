/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomEzsignfoldersignerassociationActionableElementResponse } from './custom-ezsignfoldersignerassociation-actionable-element-response';

import { DefaultObject } from '../base'

/**
 * Payload for GET /1/object/ezsignfolder/{pkiEzsignfolder}/getEzsignfoldersignerassociations
 * @export
 * @interface EzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload
 */
export interface EzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomEzsignfoldersignerassociationActionableElementResponse>}
     * @memberof EzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload
     */
    'a_objEzsignfoldersignerassociation': Array<CustomEzsignfoldersignerassociationActionableElementResponse>;
}
/**
 * A EzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload
 */
export class DefaultObjectEzsignfolderGetEzsignfoldersignerassociationsV1ResponseMPayload extends DefaultObject {
   a_objEzsignfoldersignerassociation:Array<CustomEzsignfoldersignerassociationActionableElementResponse> = []
}


