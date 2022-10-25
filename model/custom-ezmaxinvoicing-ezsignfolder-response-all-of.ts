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



import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface CustomEzmaxinvoicingEzsignfolderResponseAllOf
 */
export interface CustomEzmaxinvoicingEzsignfolderResponseAllOf {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponseAllOf
     */
    'fkiEzsignfolderID': number;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponseAllOf
     */
    'sEzsignfolderDescription': string;
    /**
     * Whether the TSA requirement is billable or not
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponseAllOf
     */
    'bEzsigntsarequirementBillable': boolean;
    /**
     * Whether the MFA was used or not for the Ezsignfolder
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponseAllOf
     */
    'bEzsignfolderMfaused': boolean;
    /**
     * Whether there was a signature is of type payment
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponseAllOf
     */
    'bEzsignfolderPaymentused': boolean;
    /**
     * 
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsignfolderResponseAllOf
     */
    'bEzsignfolderAllowed': boolean;
}
/**
 * A CustomEzmaxinvoicingEzsignfolderResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomEzmaxinvoicingEzsignfolderResponseAllOf
 */
export class DefaultObjectCustomEzmaxinvoicingEzsignfolderResponseAllOf extends DefaultObject {
   fkiEzsignfolderID:number = 0
   sEzsignfolderDescription:string = ''
   bEzsigntsarequirementBillable:boolean = false
   bEzsignfolderMfaused:boolean = false
   bEzsignfolderPaymentused:boolean = false
   bEzsignfolderAllowed:boolean = false
}


