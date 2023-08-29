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
import { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import { CustomCreditcardtransactionResponse } from './custom-creditcardtransaction-response';
// May contain unused imports in some cases
// @ts-ignore
import { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureResponse } from './ezsignsignature-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignaturecustomdateResponseCompound } from './ezsignsignaturecustomdate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureAttachmentnamesource } from './field-eezsignsignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureFont } from './field-eezsignsignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureTooltipposition } from './field-eezsignsignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureType } from './field-eezsignsignature-type';
// May contain unused imports in some cases
// @ts-ignore
import { SignatureResponseCompound } from './signature-response-compound';

/**
 * @type EzsignsignatureResponseCompound
 * An Ezsignsignature Object and children to create a complete structure
 * @export
 */
export type EzsignsignatureResponseCompound = EzsignsignatureResponse;



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomContactNameResponse } from './'
// @ts-ignore
import { DataObjectSignatureResponseCompound } from './'
// @ts-ignore
import { DataObjectCustomCreditcardtransactionResponse } from './'
// @ts-ignore
import { ValidationObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectSignatureResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCustomCreditcardtransactionResponse } from './'

/**
 * @export 
 * A EzsignsignatureResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureResponseCompound
 */
export class DataObjectEzsignsignatureResponseCompound {
    pkiEzsignsignatureID:number = 0
    fkiEzsigndocumentID:number = 0
    fkiEzsignfoldersignerassociationID:number = 0
    iEzsignpagePagenumber:number = 0
    iEzsignsignatureX:number = 0
    iEzsignsignatureY:number = 0
    iEzsignsignatureHeight?:number = undefined
    iEzsignsignatureWidth?:number = undefined
    iEzsignsignatureStep:number = 0
    eEzsignsignatureType:FieldEEzsignsignatureType = 'Acknowledgement'
    tEzsignsignatureTooltip?:string = undefined
    eEzsignsignatureTooltipposition?:FieldEEzsignsignatureTooltipposition = undefined
    eEzsignsignatureFont?:FieldEEzsignsignatureFont = undefined
    iEzsignsignatureValidationstep?:number = undefined
    sEzsignsignatureAttachmentdescription?:string = undefined
    eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource = undefined
    bEzsignsignatureRequired?:boolean = undefined
    fkiEzsignfoldersignerassociationIDValidation?:number = undefined
    dtEzsignsignatureDate?:string = undefined
    iEzsignsignatureattachmentCount?:number = undefined
    sEzsignsignatureDescription?:string = undefined
    iEzsignsignatureMaxlength?:number = undefined
    eEzsignsignatureTextvalidation?:EnumTextvalidation = undefined
    sEzsignsignatureRegexp?:string = undefined
    objContactName:CustomContactNameResponse = new DataObjectCustomContactNameResponse()
    objSignature?:SignatureResponseCompound = undefined
    bEzsignsignatureCustomdate?:boolean = undefined
    a_objEzsignsignaturecustomdate?:Array<EzsignsignaturecustomdateResponseCompound> = undefined
    objCreditcardtransaction?:CustomCreditcardtransactionResponse = undefined
}

/**
 * @export 
 * A EzsignsignatureResponseCompound Validation Object
 * @class ValidationObjectEzsignsignatureResponseCompound
 */
export class ValidationObjectEzsignsignatureResponseCompound {
   pkiEzsignsignatureID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   iEzsignsignatureX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignsignatureY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignsignatureHeight = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignsignatureWidth = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignsignatureStep = {
      type: 'integer',
      required: true
   }
   eEzsignsignatureType = {
      type: 'enum',
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','Attachments','AttachmentsConfirmation','FieldText','FieldTextarea'],
      required: true
   }
   tEzsignsignatureTooltip = {
      type: 'string',
      required: false
   }
   eEzsignsignatureTooltipposition = {
      type: 'enum',
      allowableValues: ['TopLeft','TopCenter','TopRight','MiddleLeft','MiddleRight','BottomLeft','BottomCenter','BottomRight'],
      required: false
   }
   eEzsignsignatureFont = {
      type: 'enum',
      allowableValues: ['Normal','Cursive'],
      required: false
   }
   iEzsignsignatureValidationstep = {
      type: 'integer',
      required: false
   }
   sEzsignsignatureAttachmentdescription = {
      type: 'string',
      required: false
   }
   eEzsignsignatureAttachmentnamesource = {
      type: 'enum',
      allowableValues: ['Description','Customer','DescriptionCustomer'],
      required: false
   }
   bEzsignsignatureRequired = {
      type: 'boolean',
      required: false
   }
   fkiEzsignfoldersignerassociationIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   dtEzsignsignatureDate = {
      type: 'string',
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/',
      required: false
   }
   iEzsignsignatureattachmentCount = {
      type: 'integer',
      required: false
   }
   sEzsignsignatureDescription = {
      type: 'string',
      required: false
   }
   iEzsignsignatureMaxlength = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   eEzsignsignatureTextvalidation = {
      type: 'enum',
      allowableValues: ['None','Date (YYYY-MM-DD)','Date (MM/DD/YYYY)','Date (MM/DD/YY)','Date (DD/MM/YYYY)','Date (DD/MM/YY)','Email','Letters','Numbers','Zip','Zip+4','PostalCode','Custom'],
      required: false
   }
   sEzsignsignatureRegexp = {
      type: 'string',
      required: false
   }
   objContactName = new ValidationObjectCustomContactNameResponse()
   objSignature = new ValidationObjectSignatureResponseCompound()
   bEzsignsignatureCustomdate = {
      type: 'boolean',
      required: false
   }
   a_objEzsignsignaturecustomdate = {
      type: 'array',
      required: false
   }
   objCreditcardtransaction = new ValidationObjectCustomCreditcardtransactionResponse()
} 


