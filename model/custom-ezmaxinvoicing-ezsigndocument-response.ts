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
import { CustomEzmaxinvoicingEzsigndocumentResponseAllOf } from './custom-ezmaxinvoicing-ezsigndocument-response-all-of';

import { DefaultObject } from '../base'

/**
 * @type CustomEzmaxinvoicingEzsigndocumentResponse
 * An EzmaxinvoicingEzsigndocument object containing information about the Ezmaxinvoicing for an Ezsigndocument
 * @export
 */
export type CustomEzmaxinvoicingEzsigndocumentResponse = CustomEzmaxinvoicingEzsigndocumentResponseAllOf;


/**
 * @export 
 * A CustomEzmaxinvoicingEzsigndocumentResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectCustomEzmaxinvoicingEzsigndocumentResponse
 */
export class DefaultObjectCustomEzmaxinvoicingEzsigndocumentResponse extends DefaultObject {
   fkiEzsignfolderID:number = 0
   sName:string = ''
   sEzsignfolderDescription:string = ''
   sEzsigndocumentName:string = ''
   bEzsignfolderAllowed:boolean = false
}


