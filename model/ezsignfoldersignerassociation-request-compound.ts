/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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

/**
 * @type EzsignfoldersignerassociationRequestCompound
 * An Ezsignfoldersignerassociation Object and children to create a complete structure
 * @export
 */
export type EzsignfoldersignerassociationRequestCompound = EzsignfoldersignerassociationRequest & EzsignfoldersignerassociationRequestCompoundAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignerRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignsignerRequestCompound } from './'

/**
 * @export 
 * A EzsignfoldersignerassociationRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationRequestCompound
 */
export class DataObjectEzsignfoldersignerassociationRequestCompound {
    pkiEzsignfoldersignerassociationID?:number = undefined
    fkiUserID?:number = undefined
    fkiUsergroupID?:number = undefined
    fkiEzsignsignergroupID?:number = undefined
    fkiEzsignfolderID:number = 0
    bEzsignfoldersignerassociationReceivecopy?:boolean = undefined
    tEzsignfoldersignerassociationMessage?:string = undefined
    objEzsignsigner?:EzsignsignerRequestCompound = undefined
}

/**
 * @export 
 * A EzsignfoldersignerassociationRequestCompound Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationRequestCompound
 */
export class ValidationObjectEzsignfoldersignerassociationRequestCompound {
   pkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiEzsignsignergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsignfoldersignerassociationReceivecopy = {
      type: 'boolean',
      required: false
   }
   tEzsignfoldersignerassociationMessage = {
      type: 'string',
      required: false
   }
   objEzsignsigner = new ValidationObjectEzsignsignerRequestCompound()
} 


