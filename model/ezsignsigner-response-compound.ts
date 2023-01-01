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
import { EzsignsignerResponse } from './ezsignsigner-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignerResponseCompoundAllOf } from './ezsignsigner-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignerResponseCompoundContact } from './ezsignsigner-response-compound-contact';

import { DefaultObject } from '../base'

/**
 * @type EzsignsignerResponseCompound
 * An Ezsignsigner Object and children to create a complete structure
 * @export
 */
export type EzsignsignerResponseCompound = EzsignsignerResponse & EzsignsignerResponseCompoundAllOf;


/**
 * @export 
 * A EzsignsignerResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignsignerResponseCompound
 */
export class DefaultObjectEzsignsignerResponseCompound extends DefaultObject {
   pkiEzsignsignerID:number = 0
   fkiTaxassignmentID:number = 0
   fkiSecretquestionID?:number = undefined
   fkiUserlogintypeID:number = 0
   sUserlogintypeDescriptionX:string = ''
   objContact:Partial<EzsignsignerResponseCompoundContact> = {}
}


