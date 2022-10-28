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
import { EzsignfoldersignerassociationResponse } from './ezsignfoldersignerassociation-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationResponseCompoundAllOf } from './ezsignfoldersignerassociation-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationResponseCompoundUser } from './ezsignfoldersignerassociation-response-compound-user';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignerResponseCompound } from './ezsignsigner-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsignfoldersignerassociationResponseCompound
 * An Ezsignfoldersignerassociation Object
 * @export
 */
export type EzsignfoldersignerassociationResponseCompound = EzsignfoldersignerassociationResponse & EzsignfoldersignerassociationResponseCompoundAllOf;


/**
 * @export 
 * A EzsignfoldersignerassociationResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfoldersignerassociationResponseCompound
 */
export class DefaultObjectEzsignfoldersignerassociationResponseCompound extends DefaultObject {
   pkiEzsignfoldersignerassociationID:number = 0
   fkiEzsignfolderID:number = 0
   bEzsignfoldersignerassociationReceivecopy:boolean = false
   tEzsignfoldersignerassociationMessage:string = ''
   objUser?:Partial<EzsignfoldersignerassociationResponseCompoundUser> = undefined
   objEzsignsigner?:Partial<EzsignsignerResponseCompound> = undefined
}


