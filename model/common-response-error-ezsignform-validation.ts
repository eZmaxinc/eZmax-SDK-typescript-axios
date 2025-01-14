/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseError } from './common-response-error';
// May contain unused imports in some cases
// @ts-ignore
import { CustomEzsignformfielderrorResponse } from './custom-ezsignformfielderror-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEErrorCode } from './field-eerror-code';

/**
 * @type CommonResponseErrorEzsignformValidation
 * Generic Error Message
 * @export
 */
/*export type CommonResponseErrorEzsignformValidation = CommonResponseError;*/
export interface CommonResponseErrorEzsignformValidation {
    /**
     * The message giving details about the error
     * @type {string}
     * @memberof CommonResponseErrorEzsignformValidation
     */
    sErrorMessage:string 
    /**
     * 
     * @type {FieldEErrorCode}
     * @memberof CommonResponseErrorEzsignformValidation
     */
    eErrorCode:FieldEErrorCode 
    /**
     * More error message detail
     * @type {Array<string>}
     * @memberof CommonResponseErrorEzsignformValidation
     */
    a_sErrorMessagedetail?:Array<string> 
    /**
     * 
     * @type {Array<CustomEzsignformfielderrorResponse>}
     * @memberof CommonResponseErrorEzsignformValidation
     */
    a_objEzsignformfielderror:Array<CustomEzsignformfielderrorResponse> 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonResponseErrorEzsignformValidation Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonResponseErrorEzsignformValidation
 */
export class DataObjectCommonResponseErrorEzsignformValidation {
    sErrorMessage:string = ''
    eErrorCode:FieldEErrorCode = 'BADREQUEST'
    a_sErrorMessagedetail?:Array<string> = undefined
    a_objEzsignformfielderror:Array<CustomEzsignformfielderrorResponse> = []
}

/**
 * @export 
 * A CommonResponseErrorEzsignformValidation Validation Object
 * @class ValidationObjectCommonResponseErrorEzsignformValidation
 */
export class ValidationObjectCommonResponseErrorEzsignformValidation {
   sErrorMessage = {
      type: 'string',
      pattern: /^.{0,500}$/,
      required: true
   }
   eErrorCode = {
      type: 'enum',
      allowableValues: ['BADREQUEST','BADREQUEST_CLOCKSKEW','UNAUTHORIZED_BADAUTH','UNAUTHORIZED_BADMFA','UNAUTHORIZED_EXPIRED','UNAUTHORIZED_REQUEST','FORBIDDEN','FORBIDDEN_CONFIGURATION','FORBIDDEN_MODULE','FORBIDDEN_NOACCESS','FORBIDDEN_PERMISSION','FORBIDDEN_SUBSCRIPTION','FORBIDDEN_USERTYPE','FORBIDDEN_USER_ORIGIN_EXTERNAL','NOTFOUND','NOTFOUND_OBJECT','NOTFOUND_ROUTE','METHODNOTALLOWED','NOTACCEPTABLE_CONTENT','NOTACCEPTABLE_LANGUAGE','UNPROCESSABLEENTITY_ACTIVESESSION_ALREADY_CLONING','UNPROCESSABLEENTITY_CANNOTDELETE','UNPROCESSABLEENTITY_CANNOTMODIFY','UNPROCESSABLEENTITY_CHANGEPASSWORD_INVALID_CURRENT','UNPROCESSABLEENTITY_CHANGEPASSWORD_SAME','UNPROCESSABLEENTITY_DATA_MISSING','UNPROCESSABLEENTITY_DATA_UNIQUE','UNPROCESSABLEENTITY_DATA_VALIDATION','UNPROCESSABLEENTITY_DATA_OUTOFBOUND','UNPROCESSABLEENTITY_DOWNLOAD_ERROR','UNPROCESSABLEENTITY_EZSIGNFORM_VALIDATION','UNPROCESSABLEENTITY_EZSIGNSIGNERCONNECTED','UNPROCESSABLEENTITY_NOTHINGTODO','UNPROCESSABLEENTITY_NOTREADY','UNPROCESSABLEENTITY_PDF_FORM','UNPROCESSABLEENTITY_PDF_SIGNATURE','UNPROCESSABLEENTITY_PDF_FORM_AND_SIGNATURE','UNPROCESSABLEENTITY_PDF_INCOMPATIBLE','UNPROCESSABLEENTITY_PDF_PASSWORD','UNPROCESSABLEENTITY_PDF_WRONG_PASSWORD','UNPROCESSABLEENTITY_PDF_REPAIRABLE','UNPROCESSABLEENTITY_PDF_XFA','UNPROCESSABLEENTITY_TEMPLATE_MISMATCH','UNPROCESSABLEENTITY_UNMODIFIABLE_FIELD','UNPROCESSABLEENTITY_USER_STAGED','TOOMANYREQUESTS','TOOMANYREQUESTS_THIRDPARTY','ERROR_INTERNAL','ERROR_CONFIGURATION','ERROR_NOTIMPLEMENTED'],
      required: true
   }
   a_sErrorMessagedetail = {
      type: 'array',
      required: false
   }
   a_objEzsignformfielderror = {
      type: 'array',
      required: true
   }
} 


