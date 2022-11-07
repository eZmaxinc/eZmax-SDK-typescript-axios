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
import { EzsigndocumentRequest } from './ezsigndocument-request';

import { DefaultObject } from '../base'

/**
 * @type EzsigndocumentRequestCompound
 * An Ezsigndocument Object and children to create a complete structure
 * @export
 */
export type EzsigndocumentRequestCompound = EzsigndocumentRequest;


export const EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum = {
    Base64: 'Base64',
    Ezsigntemplate: 'Ezsigntemplate',
    Url: 'Url'
} as const;
export type EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum = typeof EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum[keyof typeof EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum];

export const EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum = {
    Pdf: 'Pdf'
} as const;
export type EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum = typeof EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum[keyof typeof EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum];

export const EzsigndocumentRequestCompoundEEzsigndocumentFormEnum = {
    Keep: 'Keep',
    Convert: 'Convert'
} as const;
export type EzsigndocumentRequestCompoundEEzsigndocumentFormEnum = typeof EzsigndocumentRequestCompoundEEzsigndocumentFormEnum[keyof typeof EzsigndocumentRequestCompoundEEzsigndocumentFormEnum];


/**
 * @export 
 * A EzsigndocumentRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigndocumentRequestCompound
 */
export class DefaultObjectEzsigndocumentRequestCompound extends DefaultObject {
   pkiEzsigndocumentID?:number = undefined
   fkiEzsignfolderID:number = 0
   fkiEzsigntemplateID?:number = undefined
   fkiEzsignfoldersignerassociationID?:number = undefined
   fkiLanguageID:number = 0
   eEzsigndocumentSource:EzsigndocumentRequestCompoundEEzsigndocumentSourceEnum = 'Base64'
   eEzsigndocumentFormat?:EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum = undefined
   sEzsigndocumentBase64?:string = undefined
   sEzsigndocumentUrl?:string = undefined
   bEzsigndocumentForcerepair?:boolean = undefined
   sEzsigndocumentPassword?:string = undefined
   eEzsigndocumentForm?:EzsigndocumentRequestCompoundEEzsigndocumentFormEnum = undefined
   dtEzsigndocumentDuedate:string = ''
   sEzsigndocumentName:string = ''
}


