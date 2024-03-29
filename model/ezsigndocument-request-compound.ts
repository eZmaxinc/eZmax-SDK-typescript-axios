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
import { EzsigndocumentRequest } from './ezsigndocument-request';

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
    Pdf: 'Pdf',
    Doc: 'Doc',
    Docx: 'Docx',
    Xls: 'Xls',
    Xlsx: 'Xlsx',
    Ppt: 'Ppt',
    Pptx: 'Pptx'
} as const;
export type EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum = typeof EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum[keyof typeof EzsigndocumentRequestCompoundEEzsigndocumentFormatEnum];

export const EzsigndocumentRequestCompoundEEzsigndocumentFormEnum = {
    Keep: 'Keep',
    Convert: 'Convert'
} as const;
export type EzsigndocumentRequestCompoundEEzsigndocumentFormEnum = typeof EzsigndocumentRequestCompoundEEzsigndocumentFormEnum[keyof typeof EzsigndocumentRequestCompoundEEzsigndocumentFormEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentRequestCompound
 */
export class DataObjectEzsigndocumentRequestCompound {
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
    sEzsigndocumentExternalid?:string = undefined
}

/**
 * @export 
 * A EzsigndocumentRequestCompound Validation Object
 * @class ValidationObjectEzsigndocumentRequestCompound
 */
export class ValidationObjectEzsigndocumentRequestCompound {
   pkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   eEzsigndocumentSource = {
      type: 'enum',
      allowableValues: ['Base64','Ezsigntemplate','Url'],
      required: true
   }
   eEzsigndocumentFormat = {
      type: 'enum',
      allowableValues: ['Pdf','Doc','Docx','Xls','Xlsx','Ppt','Pptx'],
      required: false
   }
   sEzsigndocumentBase64 = {
      type: 'string',
      required: false
   }
   sEzsigndocumentUrl = {
      type: 'string',
      required: false
   }
   bEzsigndocumentForcerepair = {
      type: 'boolean',
      required: false
   }
   sEzsigndocumentPassword = {
      type: 'string',
      required: false
   }
   eEzsigndocumentForm = {
      type: 'enum',
      allowableValues: ['Keep','Convert'],
      required: false
   }
   dtEzsigndocumentDuedate = {
      type: 'string',
      required: true
   }
   sEzsigndocumentName = {
      type: 'string',
      required: true
   }
   sEzsigndocumentExternalid = {
      type: 'string',
      pattern: '/^.{0,64}$/',
      required: false
   }
} 


