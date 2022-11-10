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
import { EzsignsignerRequest } from './ezsignsigner-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignerRequestCompoundAllOf } from './ezsignsigner-request-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignerRequestCompoundContact } from './ezsignsigner-request-compound-contact';

import { DefaultObject } from '../base'

/**
 * @type EzsignsignerRequestCompound
 * An Ezsignsigner Object and children to create a complete structure
 * @export
 */
export type EzsignsignerRequestCompound = EzsignsignerRequest & EzsignsignerRequestCompoundAllOf;


export const EzsignsignerRequestCompoundEEzsignsignerLogintypeEnum = {
    Password: 'Password',
    PasswordPhone: 'PasswordPhone',
    PasswordQuestion: 'PasswordQuestion',
    InPersonPhone: 'InPersonPhone',
    InPerson: 'InPerson'
} as const;
export type EzsignsignerRequestCompoundEEzsignsignerLogintypeEnum = typeof EzsignsignerRequestCompoundEEzsignsignerLogintypeEnum[keyof typeof EzsignsignerRequestCompoundEEzsignsignerLogintypeEnum];


/**
 * @export 
 * A EzsignsignerRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignsignerRequestCompound
 */
export class DefaultObjectEzsignsignerRequestCompound extends DefaultObject {
   fkiUserlogintypeID?:number = undefined
   fkiTaxassignmentID:number = 0
   fkiSecretquestionID?:number = undefined
   eEzsignsignerLogintype?:EzsignsignerRequestCompoundEEzsignsignerLogintypeEnum = undefined
   sEzsignsignerSecretanswer?:string = undefined
   objContact:Partial<EzsignsignerRequestCompoundContact> = {}
}


