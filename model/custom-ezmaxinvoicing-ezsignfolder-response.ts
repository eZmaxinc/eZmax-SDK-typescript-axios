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
import { CustomEzmaxinvoicingEzsignfolderResponseAllOf } from './custom-ezmaxinvoicing-ezsignfolder-response-all-of';

import { DefaultObject } from '../base'

/**
 * @type CustomEzmaxinvoicingEzsignfolderResponse
 * An EzmaxinvoicingEzsignfolder object containing information about the Ezmaxinvoicing for an Ezsignfolder
 * @export
 */
export type CustomEzmaxinvoicingEzsignfolderResponse = CustomEzmaxinvoicingEzsignfolderResponseAllOf;


/**
 * @export 
 * A CustomEzmaxinvoicingEzsignfolderResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectCustomEzmaxinvoicingEzsignfolderResponse
 */
export class DefaultObjectCustomEzmaxinvoicingEzsignfolderResponse extends DefaultObject {
   fkiEzsignfolderID:number = 0
   sEzsignfolderDescription:string = ''
   bEzsigntsarequirementBillable:boolean = false
   bEzsignfolderMfaused:boolean = false
   bEzsignfolderPaymentused:boolean = false
   bEzsignfolderAllowed:boolean = false
}

