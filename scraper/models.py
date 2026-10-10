from dataclasses import dataclass


@dataclass
class SearchCriteria:
    survey_no: str = ""
    hissa_no: str = ""
    old_survey_no: str = ""
    gat_no: str = ""
    from_year: str = ""
    to_year: str = ""


@dataclass
class DocumentRecord:
    id: int
    criteria: SearchCriteria
    source_url: str
    saved_filename: str
    content_type: str
    downloaded_at: str