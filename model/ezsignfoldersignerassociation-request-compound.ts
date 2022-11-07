/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationRequest } from './ezsignfoldersignerassociation-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationRequestCompoundAllOf } from './ezsignfoldersignerassociation-request-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignerRequestCompound } from './ezsignsigner-request-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsignfoldersignerassociationRequestCompound
 * An Ezsignfoldersignerassociation Object and children to create a complete structure
 * @export
 */
export type EzsignfoldersignerassociationRequestCompound = EzsignfoldersignerassociationRequest & EzsignfoldersignerassociationRequestCompoundAllOf;


/**
 * @export 
 * A EzsignfoldersignerassociationRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignfoldersignerassociationRequestCompound
 */
export class DefaultObjectEzsignfoldersignerassociationRequestCompound extends DefaultObject {
   pkiEzsignfoldersignerassociationID?:number = undefined
   fkiUserID?:number = undefined
   fkiEzsignfolderID:number = 0
   bEzsignfoldersignerassociationReceivecopy?:boolean = undefined
   tEzsignfoldersignerassociationMessage?:string = undefined
   objEzsignsigner?:Partial<EzsignsignerRequestCompound> = undefined
}


