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
import { EzsignfoldersignerassociationResponseCompound } from './ezsignfoldersignerassociation-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationResponseCompoundUser } from './ezsignfoldersignerassociation-response-compound-user';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignerResponseCompound } from './ezsignsigner-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsignfoldersignerassociationGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}
 * @export
 */
export type EzsignfoldersignerassociationGetObjectV1ResponseMPayload = EzsignfoldersignerassociationResponseCompound;


/**
 * @export 
 * A EzsignfoldersignerassociationGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsignfoldersignerassociationGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsignfoldersignerassociationID:number = 0
   fkiEzsignfolderID:number = 0
   bEzsignfoldersignerassociationDelayedsend:boolean = false
   bEzsignfoldersignerassociationReceivecopy:boolean = false
   tEzsignfoldersignerassociationMessage:string = ''
   objUser?:Partial<EzsignfoldersignerassociationResponseCompoundUser> = undefined
   objEzsignsigner?:Partial<EzsignsignerResponseCompound> = undefined
}


