/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationResponseCompound } from './ezsignfoldersignerassociation-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /2/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}
 * @export
 * @interface EzsignfoldersignerassociationGetObjectV2ResponseMPayload
 */
export interface EzsignfoldersignerassociationGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignfoldersignerassociationResponseCompound}
     * @memberof EzsignfoldersignerassociationGetObjectV2ResponseMPayload
     */
    'objEzsignfoldersignerassociation': EzsignfoldersignerassociationResponseCompound;
}
/**
 * A EzsignfoldersignerassociationGetObjectV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldersignerassociationGetObjectV2ResponseMPayload
 */
export class DefaultObjectEzsignfoldersignerassociationGetObjectV2ResponseMPayload extends DefaultObject {
   objEzsignfoldersignerassociation:Partial<EzsignfoldersignerassociationResponseCompound> = {}
}


